"""Aplicación administrativa de DNSentinel y comandos de mantenimiento."""
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import uuid

import click
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, abort, g, jsonify, redirect, request
from werkzeug.exceptions import HTTPException

from .db import close_db, evaluate, get_db, init_db, purge_expired, serialize_rule, record_event
from .crypto_store import configure_crypto, migrate_logs, decrypt_row
from .policy import Policy
from .lists import import_list, MAX_RULES
from .security import (COOKIE, cookie_name, audit, check_csrf, issue_session, load_session,
                       rate_limit, require_admin, revoke_session, utc_now)
from .validation import InvalidInput, domain_name, object_fields, password_policy, rule_input, username


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True, static_url_path='/static')
    app.config.from_mapping(
        DATABASE=str(Path(app.instance_path) / 'dnsentinel.sqlite3'),
        MAX_CONTENT_LENGTH=1064960,
        TRUSTED_HOSTS=['localhost', '127.0.0.1'],
        SESSION_COOKIE_SECURE=os.getenv('DNSENTINEL_COOKIE_SECURE', '1') == '1',
        TESTING=False,
        DNS_STATUS={'running': False},
    )
    if test_config:
        app.config.update(test_config)
    instance = Path(app.instance_path)
    instance.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Clave local de seudonimización; no se incluye en el paquete ni en Git.
    key_path = instance / 'rate-limit.key'
    if 'RATE_KEY' not in app.config:
        try:
            with key_path.open('xb') as file:
                file.write(secrets.token_bytes(32))
            key_path.chmod(0o600)
        except FileExistsError:
            pass
        app.config['RATE_KEY'] = key_path.read_bytes()
    configure_crypto(app)
    app.extensions['policy'] = Policy()
    app.teardown_appcontext(close_db)
    app.extensions['password_hasher'] = PasswordHasher()
    # Hash ficticio de coste equivalente para usuarios inexistentes.
    dummy = app.extensions['password_hasher'].hash(secrets.token_urlsafe(32))
    with app.app_context():
        init_db()
        migrate_logs(get_db())
        purge_expired()
        app.extensions['policy'].refresh()

    maintenance = {'last': 0.0}
    maintenance_lock = threading.Lock()

    @app.before_request
    def protect_request():
        g.request_id = uuid.uuid4().hex
        g.user = None
        # Purga al iniciar y como máximo una vez al día mientras llegan solicitudes.
        with maintenance_lock:
            if time.monotonic() - maintenance['last'] > 86400:
                purge_expired()
                maintenance['last'] = time.monotonic()
        load_session()
        if request.path != '/api/rules/import' and request.content_length and request.content_length > 8192:
            abort(413)
        if not request.path.startswith('/api/'):
            return None
        if request.path not in ('/api/session', '/api/login') and g.user is None:
            abort(401, description='Inicia sesión para continuar.')
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            check_csrf()
        return None

    @app.after_request
    def security_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if getattr(g, 'clear_cookie', False):
            response.delete_cookie(cookie_name(), path='/', httponly=True, samesite='Strict',
                                   secure=app.config['SESSION_COOKIE_SECURE'])
        if getattr(g, 'new_cookie', None):
            response.set_cookie(cookie_name(), g.new_cookie, httponly=True, samesite='Strict',
                                secure=app.config['SESSION_COOKIE_SECURE'], path='/')
        return response

    @app.errorhandler(InvalidInput)
    def invalid_input(error):
        audit('input_validation', 'rejected')
        return jsonify(error=str(error), request_id=g.request_id), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        if error.code in (400, 413, 415):
            audit('request_rejected', 'rejected', str(error.code))
        messages = {400: 'Solicitud no válida.', 404: 'Recurso no encontrado.',
                    405: 'Método no permitido.', 413: 'La solicitud supera el tamaño permitido.',
                    415: 'Envía un cuerpo JSON válido.'}
        return jsonify(error=messages.get(error.code, error.description), request_id=g.request_id), error.code

    @app.errorhandler(Exception)
    def unexpected_error(error):
        # No registrar str(error), SQL, cuerpos, contraseñas ni tokens.
        get_db().rollback()
        logging.getLogger('dnsentinel').error('incident=%s exception_class=%s',
                                             g.request_id, type(error).__name__)
        return jsonify(error='Ocurrió un error interno. Comunica el identificador al administrador.',
                       request_id=g.request_id), 500

    def json_body():
        if not request.is_json:
            abort(415)
        return request.get_json()

    @app.get('/')
    def index():
        if g.user is None:
            return redirect('/login')
        return app.send_static_file('index.html')

    @app.get('/login')
    def login_page():
        return app.send_static_file('login.html')

    @app.get('/api/session')
    def session_info():
        if g.server_session is None:
            rate_limit('anonymous_session', request.remote_addr or 'local', 30, 60)
            csrf = issue_session()
        else:
            csrf = g.server_session['csrf']
        user = dict(g.user) if g.user is not None else None
        return jsonify(user=user, csrf=csrf)

    @app.post('/api/login')
    def login():
        data = object_fields(json_body(), ('username', 'password'))
        name = username(data['username'])
        # Acota las entradas antes de ejecutar el hash de coste elevado.
        if not isinstance(data['password'], str) or not 1 <= len(data['password']) <= 128:
            raise InvalidInput('Credenciales inválidas.')
        rate_limit('login_origin', request.remote_addr or 'local', 20, 900)
        rate_limit('login_account', name, 5, 900)
        user = get_db().execute('SELECT * FROM users WHERE username = ?', (name,)).fetchone()
        hasher = app.extensions['password_hasher']
        try:
            hasher.verify(user['password_hash'] if user is not None else dummy, data['password'])
        except (VerificationError, InvalidHashError):
            audit('login', 'failed')
            abort(401, description='Credenciales inválidas.')
        if user is None:
            abort(401, description='Credenciales inválidas.')
        if hasher.check_needs_rehash(user['password_hash']):
            get_db().execute('UPDATE users SET password_hash = ? WHERE id = ?',
                             (hasher.hash(data['password']), user['id']))
            get_db().commit()
        revoke_session()
        csrf = issue_session(user['id'])
        g.user = user
        audit('login', 'success')
        return jsonify(user={'id': user['id'], 'username': user['username'], 'role': user['role']}, csrf=csrf)

    @app.post('/api/logout')
    def logout():
        audit('logout', 'success')
        revoke_session()
        return jsonify(ok=True)

    @app.get('/api/rules')
    def rules_list():
        return jsonify(rules=[serialize_rule(r) for r in get_db().execute('SELECT * FROM rules ORDER BY id DESC')])

    @app.post('/api/rules')
    def rule_create():
        require_admin()
        data = rule_input(json_body())
        db = get_db()
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT count(*) FROM rules').fetchone()[0] >= MAX_RULES:
            db.rollback()
            abort(409, description='Se alcanzó el límite de reglas del laboratorio.')
        try:
            cur = db.execute('INSERT INTO rules(domain,kind,note,subdomains,active) VALUES (?,?,?,?,?)',
                             tuple(data[k] for k in ('domain', 'kind', 'note', 'subdomains', 'active')))
        except sqlite3.IntegrityError:
            db.rollback()
            abort(409, description='Ya existe una regla de este tipo para el dominio.')
        audit('rule_create', 'success', f'id={cur.lastrowid};domain={data["domain"]};kind={data["kind"]}')
        app.extensions['policy'].refresh()
        return jsonify(ok=True, id=cur.lastrowid), 201

    @app.put('/api/rules/<int:rule_id>')
    def rule_update(rule_id):
        require_admin()
        data = rule_input(json_body())
        db = get_db()
        old = db.execute('SELECT * FROM rules WHERE id = ?', (rule_id,)).fetchone()
        if old is None:
            abort(404)
        try:
            db.execute('UPDATE rules SET domain=?,kind=?,note=?,subdomains=?,active=? WHERE id=?',
                        (*tuple(data[k] for k in ('domain', 'kind', 'note', 'subdomains', 'active')), rule_id))
        except sqlite3.IntegrityError:
            db.rollback()
            abort(409, description='Ya existe una regla de este tipo para el dominio.')
        detail = (f'id={rule_id};before={old["domain"]},{old["kind"]},{old["active"]},{old["subdomains"]};'
                  f'after={data["domain"]},{data["kind"]},{int(data["active"])},{int(data["subdomains"])}')
        audit('rule_update', 'success', detail)
        app.extensions['policy'].refresh()
        return jsonify(ok=True)

    @app.delete('/api/rules/<int:rule_id>')
    def rule_delete(rule_id):
        require_admin()
        db = get_db()
        old = db.execute('SELECT * FROM rules WHERE id = ?', (rule_id,)).fetchone()
        if old is None:
            abort(404)
        db.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        audit('rule_delete', 'success', f'id={rule_id};domain={old["domain"]};kind={old["kind"]}')
        app.extensions['policy'].refresh()
        return jsonify(ok=True)

    @app.post('/api/simulate')
    def simulate():
        rate_limit('simulation', str(g.user['id']), 60, 60)
        data = object_fields(json_body(), ('domain', 'type', 'transport'))
        domain = domain_name(data['domain'])
        if data['type'] not in ('A', 'AAAA', 'MX', 'TXT') or data['transport'] not in ('UDP', 'TCP'):
            raise InvalidInput('Tipo de registro o transporte no admitido.')
        result = evaluate(domain)
        event = record_event(domain, data['type'], data['transport'], result['decision'], result['reason'], mode='simulated')
        return jsonify(event=event, simulated=True)

    @app.get('/api/events')
    def events():
        return jsonify(logs=[decrypt_row(r, 'events') for r in get_db().execute(
            'SELECT id,time,domain,type,transport,decision,reason,client,mode FROM events ORDER BY id DESC LIMIT 2000')])

    @app.get('/api/audit')
    def audit_list():
        require_admin()
        return jsonify(audit=[decrypt_row(r, 'audit') for r in get_db().execute(
            'SELECT id,time,actor,action,result,detail FROM audit ORDER BY id DESC LIMIT 200')])

    @app.cli.command('create-user')
    @click.argument('name')
    @click.option('--role', type=click.Choice(['admin', 'viewer']), default='admin')
    @click.password_option(confirmation_prompt=True)
    def create_user(name, role, password):
        """Crea un usuario con contraseña solicitada de forma interactiva."""
        try:
            name = username(name)
            password_policy(password)
            db = get_db()
            db.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                        (name, app.extensions['password_hasher'].hash(password), role))
            db.commit()
        except InvalidInput as error:
            raise click.ClickException(str(error)) from error
        except sqlite3.IntegrityError as error:
            raise click.ClickException('Ese nombre de usuario ya existe. Elige otro o usa reset-password.') from error
        click.echo(f'Usuario {name} creado con rol {role}.')

    @app.cli.command('seed-demo')
    def seed_demo():
        """Agrega únicamente dominios .test. No borra ni reemplaza reglas existentes."""
        db = get_db()
        for domain, kind, note, subdomains in [
            ('malware.test', 'block', 'Dominio reservado de prueba', True),
            ('phishing.test', 'block', 'Dominio reservado de prueba', True),
            ('seguro.malware.test', 'allow', 'Excepción de prueba', False)]:
            db.execute('INSERT OR IGNORE INTO rules(domain,kind,note,subdomains,active) VALUES (?,?,?,?,1)',
                        (domain, kind, note, subdomains))
        db.commit()
        app.extensions['policy'].refresh()
        click.echo('Reglas de prueba agregadas. No se modificaron reglas existentes.')

    @app.cli.command('purge-expired')
    def purge_command():
        """Elimina eventos vencidos. Programar diariamente si el servicio permanece inactivo."""
        purge_expired()
        click.echo('Mantenimiento completado: retención de 7 días.')

    @app.get('/api/status')
    def service_status():
        return jsonify(dns=app.config['DNS_STATUS'], encrypted_logs=True, https=request.is_secure,
                       rule_limit=MAX_RULES)

    @app.post('/api/rules/import')
    def import_rules():
        require_admin()
        rate_limit('import', str(g.user['id']), 5, 60)
        file = request.files.get('file')
        if file is None:
            raise InvalidInput('Selecciona un archivo .txt de dominios o formato hosts.')
        try:
            text = file.read(1024 * 1024 + 1).decode('utf-8-sig')
        except UnicodeDecodeError:
            raise InvalidInput('El archivo debe estar codificado en UTF-8.') from None
        scope = request.form.get('subdomains', 'true')
        if scope not in ('true', 'false'):
            raise InvalidInput('El alcance de subdominios debe ser true o false.')
        result = import_list(text, request.form.get('kind', 'block'), scope == 'true')
        audit('rules_import', 'success', f'added={result["added"]};existing={result["existing"]};ignored={result["ignored"]}')
        return jsonify(**result)

    @app.cli.command('reset-password')
    @click.argument('name')
    @click.password_option(confirmation_prompt=True)
    def reset_password(name, password):
        """Recuperación local por el propietario del servidor; revoca todas las sesiones del usuario."""
        try:
            name = username(name)
            password_policy(password)
        except InvalidInput as error:
            raise click.ClickException(str(error)) from error
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE username=?', (name,)).fetchone()
        if user is None:
            raise click.ClickException('El usuario no existe.')
        db.execute('UPDATE users SET password_hash=? WHERE id=?', (app.extensions['password_hasher'].hash(password), user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
        audit('password_reset_local', 'success', 'user_id=' + str(user['id']))
        click.echo('Contraseña actualizada y sesiones revocadas.')

    return app
