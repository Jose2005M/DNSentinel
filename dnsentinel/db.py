"""SQLite local: consultas parametrizadas, límites y mantenimiento."""
import sqlite3
import time
from flask import current_app, g
from .crypto_store import seal

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','viewer')));
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, user_id INTEGER REFERENCES users(id),
 created REAL NOT NULL, last_seen REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS rules (
 id INTEGER PRIMARY KEY, domain TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('block','allow')),
 note TEXT NOT NULL, subdomains INTEGER NOT NULL CHECK(subdomains IN (0,1)),
 active INTEGER NOT NULL CHECK(active IN (0,1)), UNIQUE(domain,kind));
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, time TEXT NOT NULL, domain TEXT NOT NULL,
 type TEXT NOT NULL, transport TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL,
 created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, time TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits (
 bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL);
CREATE INDEX IF NOT EXISTS audit_created ON audit(created);
CREATE INDEX IF NOT EXISTS events_created ON events(created);
'''


def get_db():
    if 'db' not in g:
        connection = sqlite3.connect(current_app.config['DATABASE'], timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys = ON')
        connection.execute('PRAGMA secure_delete = ON')
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop('db', None)
    if connection is not None:
        connection.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.execute('PRAGMA journal_mode = WAL')
    columns = {r[1] for r in db.execute('PRAGMA table_info(events)')}
    if 'client' not in columns:
        db.execute("ALTER TABLE events ADD COLUMN client TEXT NOT NULL DEFAULT 'local'")
    if 'mode' not in columns:
        db.execute("ALTER TABLE events ADD COLUMN mode TEXT NOT NULL DEFAULT 'simulated'")
    db.commit()


def purge_expired():
    now = time.time()
    cutoff = now - 7 * 24 * 3600
    db = get_db()
    db.execute('DELETE FROM audit WHERE created < ?', (cutoff,))
    db.execute('DELETE FROM events WHERE created < ?', (cutoff,))
    db.execute('DELETE FROM sessions WHERE expires < ? OR last_seen < ?', (now, now - 900))
    db.execute('DELETE FROM rate_limits WHERE reset < ?', (now,))
    db.commit()


def serialize_rule(row):
    return {**dict(row), 'active': bool(row['active']), 'subdomains': bool(row['subdomains'])}


def evaluate(domain):
    return current_app.extensions['policy'].evaluate(domain)


def record_event(domain, kind, transport, decision, reason, client='local', mode='real'):
    from .security import utc_now
    event = dict(time=utc_now(), domain=domain, type=kind, transport=transport,
                 decision=decision, reason=reason, client=client, mode=mode)
    values = [seal(event[field], 'events.' + field) for field in event]
    db = get_db()
    db.execute('INSERT INTO events(time,domain,type,transport,decision,reason,client,mode,created) VALUES (?,?,?,?,?,?,?,?,?)',
               (*values, time.time()))
    db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)')
    db.commit()
    return event
