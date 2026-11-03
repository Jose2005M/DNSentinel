"""Sesiones opacas revocables, CSRF, auditoría y límites de intentos."""
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from flask import abort, current_app, g, request
from .db import get_db

COOKIE = 'dnsentinel_session'


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    # SHA-256 es apropiado para tokens aleatorios; las contraseñas usan Argon2id.
    return hashlib.sha256(value.encode()).hexdigest()


def audit(action, result, detail=''):
    user = getattr(g, 'user', None)
    actor = user['username'] if user is not None else 'anonymous'
    db = get_db()
    db.execute('INSERT INTO audit(time,actor,action,result,detail,created) VALUES (?,?,?,?,?,?)',
               (utc_now(), actor, action, result, detail, time.time()))
    # Los detalles son definidos por la aplicación, nunca contienen el cuerpo de la petición.
    db.execute('DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 10000)')
    db.commit()


def issue_session(user_id=None):
    now = time.time()
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    get_db().execute('INSERT INTO sessions VALUES (?,?,?,?,?,?)',
                     (digest(token), csrf, user_id, now, now, now + (28800 if user_id else 900)))
    get_db().commit()
    g.new_cookie = token
    return csrf


def load_session():
    g.user = None
    g.server_session = None
    token = request.cookies.get(COOKIE, '')
    if not token or len(token) > 128:
        return
    db = get_db()
    session = db.execute('SELECT * FROM sessions WHERE token_hash = ?', (digest(token),)).fetchone()
    if session is None:
        return
    now = time.time()
    if session['expires'] <= now or now - session['last_seen'] >= 900:
        db.execute('DELETE FROM sessions WHERE token_hash = ?', (session['token_hash'],))
        db.commit()
        return
    if session['user_id'] is not None:
        g.user = db.execute('SELECT id,username,role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    g.server_session = session
    db.execute('UPDATE sessions SET last_seen = ? WHERE token_hash = ?', (now, session['token_hash']))
    db.commit()


def revoke_session():
    if g.server_session is not None:
        get_db().execute('DELETE FROM sessions WHERE token_hash = ?', (g.server_session['token_hash'],))
        get_db().commit()
    g.clear_cookie = True


def check_csrf():
    supplied = request.headers.get('X-CSRF-Token', '')
    session = g.server_session
    origin = request.headers.get('Origin')
    if (session is None or not supplied.isascii() or len(supplied) > 128 or
            not hmac.compare_digest(supplied, session['csrf']) or
            (origin is not None and origin != request.host_url.rstrip('/'))):
        audit('csrf_rejected', 'denied')
        abort(403, description='Solicitud no autorizada. Actualiza la página e inténtalo de nuevo.')


def require_admin():
    if g.user is None or g.user['role'] != 'admin':
        audit('authorization', 'denied', 'admin_required')
        abort(403, description='Tu cuenta no tiene permiso para esta operación.')


def rate_limit(scope, identity, limit, period):
    # Seudonimiza origen/usuario en los contadores; no conserva direcciones IP.
    bucket = hmac.new(current_app.config['RATE_KEY'], (scope + ':' + identity).encode(), hashlib.sha256).hexdigest()
    now = time.time()
    db = get_db()
    db.execute('''INSERT INTO rate_limits(bucket,count,reset) VALUES (?,1,?)
       ON CONFLICT(bucket) DO UPDATE SET
       count=CASE WHEN reset <= ? THEN 1 ELSE count+1 END,
       reset=CASE WHEN reset <= ? THEN excluded.reset ELSE reset END''',
               (bucket, now + period, now, now))
    count = db.execute('SELECT count FROM rate_limits WHERE bucket = ?', (bucket,)).fetchone()['count']
    db.commit()
    if count > limit:
        audit('rate_limit', 'denied', scope)
        abort(429, description='Demasiados intentos. Espera antes de volver a intentarlo.')
