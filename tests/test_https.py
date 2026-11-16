"""HTTPS real con validación de certificado, API autenticada e importación."""
import http.client
import json
import secrets
import socket
import ssl
import threading
import time
from pathlib import Path

from cheroot.ssl.builtin import BuiltinSSLAdapter
from cheroot.wsgi import Server

from dnsentinel import create_app
from dnsentinel.db import get_db
from setup_tls import create_certificate


def test_verified_https_cookie_csrf_and_import(tmp_path):
    ca = create_certificate(tmp_path/'tls')
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path/'secure.sqlite3'),
                      'SESSION_COOKIE_SECURE': True,
                      'RATE_KEY': secrets.token_bytes(32), 'DATA_KEY': secrets.token_bytes(32)})
    password = secrets.token_urlsafe(24)
    with app.app_context():
        db = get_db()
        db.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                   ('admin', app.extensions['password_hasher'].hash(password), 'admin'))
        db.commit()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    web = Server(('127.0.0.1', port), app, numthreads=2, server_name='localhost')
    web.ssl_adapter = BuiltinSSLAdapter(str(tmp_path/'tls/server-cert.pem'), str(tmp_path/'tls/server-key.pem'))
    web.ssl_adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    web.prepare()
    thread = threading.Thread(target=web.serve, daemon=True)
    thread.start()
    context = ssl.create_default_context(cafile=str(ca))
    connection = http.client.HTTPSConnection('localhost', port, context=context, timeout=5)
    cookie = ''
    def request(path, method='GET', body=None, headers=None):
        nonlocal cookie
        connection.request(method, path, body=body, headers={'Cookie': cookie, **(headers or {})})
        response = connection.getresponse()
        data = response.read()
        updated = next((value for name,value in reversed(response.getheaders()) if name.lower() == 'set-cookie'), None)
        if updated:
            cookie = updated.split(';')[0]
        return response, data
    try:
        response, html = request('/login')
        assert response.status == 200 and b'Iniciar sesi' in html
        assert response.getheader('Strict-Transport-Security')
        response, body = request('/api/session')
        csrf = json.loads(body)['csrf']
        assert 'Secure' in response.getheader('Set-Cookie')
        response, body = request('/api/login', 'POST', json.dumps({'username':'admin','password':password}),
                                 {'Content-Type':'application/json','X-CSRF-Token':csrf})
        assert response.status == 200
        csrf = json.loads(body)['csrf']
        response, body = request('/api/status')
        assert response.status == 200 and json.loads(body)['https'] is True
        boundary = '----dnsentinel' + secrets.token_hex(16)
        multipart = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="list.txt"\r\n'
                     f'Content-Type: text/plain\r\n\r\nimported.test\n0.0.0.0 other.test\r\n--{boundary}--\r\n').encode()
        response, body = request('/api/rules/import', 'POST', multipart,
                                 {'Content-Type':f'multipart/form-data; boundary={boundary}','X-CSRF-Token':csrf})
        assert response.status == 200 and json.loads(body)['added'] == 2
        response, body = request('/api/rules')
        assert len(json.loads(body)['rules']) == 2
        response, body = request('/api/rules/import', 'POST', multipart,
                                 {'Content-Type':f'multipart/form-data; boundary={boundary}'})
        assert response.status == 403
        for path in ['/static/app.js','/static/api.js','/static/styles.css']:
            response, body = request(path)
            assert response.status == 200 and body
    finally:
        connection.close()
        web.stop()
        thread.join(5)
        assert not thread.is_alive()
