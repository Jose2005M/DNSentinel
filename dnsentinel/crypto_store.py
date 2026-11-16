"""Cifrado autenticado AES-256-GCM para consultas y auditoría en reposo."""
import base64
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

PREFIX = 'enc:v1:'


def configure_crypto(app):
    if app.config.get('DATA_KEY') is not None:
        key = app.config['DATA_KEY']
    else:
        base = Path(os.getenv('LOCALAPPDATA') or (Path.home() / '.local' / 'share')) / 'DNSentinel'
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = Path(os.getenv('DNSENTINEL_KEY_FILE') or base / 'data.key')
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as file:
                    file.write(base64.urlsafe_b64encode(secrets.token_bytes(32)))
            except FileExistsError:
                # Otra instancia terminó de crear la clave: usar la misma.
                if not path.is_file():
                    raise
        key = base64.urlsafe_b64decode(path.read_bytes())
        app.config['DATA_KEY_FILE'] = str(path)
    if not isinstance(key, bytes) or len(key) != 32:
        raise RuntimeError('La clave de cifrado debe contener 32 bytes.')
    app.extensions['data_cipher'] = AESGCM(key)


def seal(value, field):
    nonce = secrets.token_bytes(12)
    ciphertext = current_app.extensions['data_cipher'].encrypt(nonce, str(value).encode(), field.encode())
    return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode()


def reveal(value, field):
    if not value.startswith(PREFIX):
        raise ValueError('Registro sin cifrar: ejecuta la migración antes de leerlo.')
    data = base64.urlsafe_b64decode(value[len(PREFIX):])
    return current_app.extensions['data_cipher'].decrypt(data[:12], data[12:], field.encode()).decode()


def decrypt_row(row, table):
    fields = ('time', 'domain', 'type', 'transport', 'decision', 'reason', 'client', 'mode') if table == 'events' else ('time', 'actor', 'action', 'result', 'detail')
    data = dict(row)
    for field in fields:
        if field in data:
            data[field] = reveal(data[field], table + '.' + field)
    return data


def migrate_logs(db):
    """Migración transaccional de registros v0.2; valida la clave de los existentes."""
    changed = False
    definitions = (
        ('events', 'SELECT * FROM events',
         ('time', 'domain', 'type', 'transport', 'decision', 'reason', 'client', 'mode'),
         'UPDATE events SET time=?,domain=?,type=?,transport=?,decision=?,reason=?,client=?,mode=? WHERE id=?'),
        ('audit', 'SELECT * FROM audit', ('time', 'actor', 'action', 'result', 'detail'),
         'UPDATE audit SET time=?,actor=?,action=?,result=?,detail=? WHERE id=?'))
    for table, select, fields, update in definitions:
        for row in db.execute(select).fetchall():
            values, plaintext = [], False
            for field in fields:
                value = row[field]
                if value.startswith(PREFIX):
                    reveal(value, table + '.' + field)
                    values.append(value)
                else:
                    plaintext = True
                    values.append(seal(value, table + '.' + field))
            if plaintext:
                db.execute(update, (*values, row['id']))
                changed = True
    db.commit()
    if changed:
        # Reducir remanentes de la migración en SQLite; no elimina copias externas.
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.execute('VACUUM')
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
