"""Pruebas de integración: evaden la interfaz y atacan directamente la API."""
import json
from pathlib import Path
import secrets
import time

import pytest
from dnsentinel import create_app
from dnsentinel.db import get_db
from dnsentinel.security import COOKIE, digest


@pytest.fixture
def app(tmp_path):
    application = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'test.sqlite3'),
                              'RATE_KEY': secrets.token_bytes(32)})
    application.credentials = {}
    with application.app_context():
        db = get_db()
        for name, role in [('admin', 'admin'), ('lector', 'viewer')]:
            password = secrets.token_urlsafe(24)
            application.credentials[name] = password
            db.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                        (name, application.extensions['password_hasher'].hash(password), role))
        db.commit()
    return application


def sign_in(client, app, name='admin'):
    csrf = client.get('/api/session').json['csrf']
    response = client.post('/api/login', json={'username': name, 'password': app.credentials[name]},
                            headers={'X-CSRF-Token': csrf})
    assert response.status_code == 200
    return {'X-CSRF-Token': response.json['csrf']}


def rule(domain='malware.test', kind='block', **updates):
    return {'domain': domain, 'kind': kind, 'note': 'Prueba de integración',
            'subdomains': True, 'active': True, **updates}


def test_authentication_required(app):
    client = app.test_client()
    assert client.get('/').status_code == 302
    for path in ['/api/rules', '/api/events', '/api/audit']:
        assert client.get(path).status_code == 401
    assert client.post('/api/rules', json=rule()).status_code == 401


def test_csrf_required_on_login_and_changes(app):
    client = app.test_client()
    assert client.post('/api/login', json={}).status_code == 403
    sign_in(client, app)
    assert client.post('/api/rules', json=rule()).status_code == 403


def test_cross_origin_rejected(app):
    client = app.test_client()
    headers = sign_in(client, app)
    assert client.post('/api/rules', json=rule(), headers={**headers, 'Origin': 'https://otro.test'}).status_code == 403
    assert client.post('/api/rules', json=rule(), headers={'X-CSRF-Token': 'ñ'}).status_code == 403


@pytest.mark.parametrize('bad', ['https://malware.test', 'malware.test/ruta', '192.168.1.1',
                                'bad..test', '-bad.test', 'a' * 64 + '.test', 'x.test;DROP TABLE rules'])
def test_server_validation_rejects_bad_domains(app, bad):
    client = app.test_client()
    headers = sign_in(client, app)
    assert client.post('/api/rules', json=rule(bad), headers=headers).status_code == 400
    assert client.get('/api/rules').json['rules'] == []
    entries = client.get('/api/audit').json['audit']
    assert any(e['action'] == 'input_validation' for e in entries)
    assert bad not in json.dumps(entries)


def test_strict_types_unknown_fields_and_size(app):
    client = app.test_client()
    headers = sign_in(client, app)
    for payload in [rule(active='false'), rule(subdomains=1), rule(note='x\n'),
                    rule(note='x' * 121), {**rule(), 'role': 'admin'}, []]:
        assert client.post('/api/rules', json=payload, headers=headers).status_code == 400
    assert client.post('/api/rules', data='x' * 9000, content_type='application/json', headers=headers).status_code == 413


def test_policy_crud_persistence_and_allowlist_priority(app):
    client = app.test_client()
    headers = sign_in(client, app)
    blocked_id = client.post('/api/rules', json=rule(' Malware.TEST. '), headers=headers).json['id']
    client.post('/api/rules', json=rule('seguro.malware.test', 'allow', subdomains=False), headers=headers)
    for domain, expected in [('malware.test', 'blocked'), ('sub.malware.test', 'blocked'),
                             ('seguro.malware.test', 'allowed'), ('notmalware.test', 'allowed')]:
        result = client.post('/api/simulate', json={'domain': domain, 'type': 'A', 'transport': 'UDP'}, headers=headers)
        assert result.status_code == 200
        assert result.json['event']['decision'] == expected
        assert result.json['simulated'] is True
    # Otra conexión de cliente ve los mismos datos; no dependen de localStorage.
    second = app.test_client()
    sign_in(second, app)
    assert len(second.get('/api/rules').json['rules']) == 2
    assert len(second.get('/api/events').json['logs']) == 4
    assert client.put(f'/api/rules/{blocked_id}', json=rule(active=False), headers=headers).status_code == 200
    result = client.post('/api/simulate', json={'domain': 'malware.test', 'type': 'AAAA', 'transport': 'TCP'}, headers=headers)
    assert result.json['event']['decision'] == 'allowed'
    assert client.delete(f'/api/rules/{blocked_id}', headers=headers).status_code == 200
    assert len(client.get('/api/rules').json['rules']) == 1
    actions = [r['action'] for r in client.get('/api/audit').json['audit']]
    assert all(a in actions for a in ['rule_create', 'rule_update', 'rule_delete'])


def test_duplicate_rule_handled_without_sql_leak(app):
    client = app.test_client()
    headers = sign_in(client, app)
    assert client.post('/api/rules', json=rule(), headers=headers).status_code == 201
    response = client.post('/api/rules', json=rule(), headers=headers)
    assert response.status_code == 409
    assert 'sqlite' not in response.get_data(as_text=True).lower()


def test_viewer_cannot_modify_or_read_audit(app):
    client = app.test_client()
    headers = sign_in(client, app, 'lector')
    assert client.get('/api/rules').status_code == 200
    assert client.get('/api/audit').status_code == 403
    for method, path in [('post', '/api/rules'), ('put', '/api/rules/1'), ('delete', '/api/rules/1')]:
        assert getattr(client, method)(path, json=rule(), headers=headers).status_code == 403


def test_password_hash_and_failure_audit_exclude_credentials(app):
    client = app.test_client()
    csrf = client.get('/api/session').json['csrf']
    attempted = secrets.token_urlsafe(20)
    response = client.post('/api/login', json={'username': 'admin', 'password': attempted},
                           headers={'X-CSRF-Token': csrf})
    assert response.status_code == 401
    with app.app_context():
        db = get_db()
        stored = db.execute('SELECT password_hash FROM users WHERE username=?', ('admin',)).fetchone()[0]
        assert stored.startswith('$argon2id$')
        assert app.credentials['admin'] not in stored
        events = str([dict(r) for r in db.execute('SELECT * FROM audit')])
        assert attempted not in events and csrf not in events
        assert 'failed' in events


def test_login_attempts_are_limited(app):
    client = app.test_client()
    csrf = client.get('/api/session').json['csrf']
    for _ in range(5):
        assert client.post('/api/login', json={'username': 'admin', 'password': secrets.token_urlsafe(20)},
                            headers={'X-CSRF-Token': csrf}).status_code == 401
    assert client.post('/api/login', json={'username': 'admin', 'password': app.credentials['admin']},
                       headers={'X-CSRF-Token': csrf}).status_code == 429


def test_logout_revokes_server_session_and_cookie_flags(app):
    client = app.test_client()
    headers = sign_in(client, app)
    cookie = client.get_cookie(COOKIE)
    assert cookie.http_only and cookie.same_site == 'Strict'
    stolen = cookie.value
    assert client.post('/api/logout', headers=headers).status_code == 200
    replay = app.test_client()
    replay.set_cookie(COOKIE, stolen)
    assert replay.get('/api/rules').status_code == 401


@pytest.mark.parametrize('mode', ['idle', 'absolute'])
def test_expired_sessions_denied(app, mode):
    client = app.test_client()
    sign_in(client, app)
    token = client.get_cookie(COOKIE).value
    with app.app_context():
        db = get_db()
        if mode == 'idle':
            db.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?', (time.time() - 901, digest(token)))
        else:
            db.execute('UPDATE sessions SET expires=? WHERE token_hash=?', (time.time() - 1, digest(token)))
        db.commit()
    assert client.get('/api/rules').status_code == 401


def test_generic_unexpected_error_no_leak(app, caplog):
    @app.get('/api/test-error')
    def broken():
        raise RuntimeError('private-internal-value')
    client = app.test_client()
    sign_in(client, app)
    response = client.get('/api/test-error')
    assert response.status_code == 500
    assert response.json['request_id']
    assert 'private-internal-value' not in response.get_data(as_text=True)
    assert 'private-internal-value' not in caplog.text
    assert 'RuntimeError' in caplog.text


def test_security_headers_static_assets_and_login(app):
    client = app.test_client()
    response = client.get('/login')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert client.get('/static/app.js').status_code == 200
    assert client.get('/static/styles.css').status_code == 200
    sign_in(client, app)
    assert b'/static/api.js' in client.get('/').data
    assert b'localStorage' not in client.get('/static/app.js').data


def test_cli_rejects_weak_password_and_creates_viewer(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=['create-user', 'nuevo', '--role', 'viewer'], input='short\nshort\n')
    assert result.exit_code != 0
    password = secrets.token_urlsafe(24)
    result = runner.invoke(args=['create-user', 'nuevo', '--role', 'viewer'], input=password+'\n'+password+'\n')
    assert result.exit_code == 0
    assert password not in result.output


def test_purge_removes_only_expired_audit(app):
    with app.app_context():
        db = get_db()
        for created in [time.time() - 8 * 86400, time.time()]:
            db.execute('INSERT INTO audit(time,actor,action,result,detail,created) VALUES (?,?,?,?,?,?)',
                        ('test', 'test', 'test', 'test', '', created))
        db.commit()
    assert app.test_cli_runner().invoke(args=['purge-expired']).exit_code == 0
    with app.app_context():
        assert get_db().execute('SELECT count(*) FROM audit').fetchone()[0] == 1


def test_fresh_instance_reads_same_database(app):
    client = app.test_client()
    headers = sign_in(client, app)
    client.post('/api/rules', json=rule(), headers=headers)
    other = create_app({'TESTING': True, 'DATABASE': app.config['DATABASE'], 'RATE_KEY': secrets.token_bytes(32)})
    with other.app_context():
        assert get_db().execute('SELECT domain FROM rules').fetchone()[0] == 'malware.test'
