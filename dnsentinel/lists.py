"""Importación explícita de listas de dominios o formato hosts. Sin descarga de URL."""
import sqlite3
from flask import current_app
from .db import get_db
from .validation import InvalidInput, domain_name

MAX_RULES = 5000


def parse_list(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 1024 * 1024:
        raise InvalidInput('La lista admite como máximo 1 MiB de texto UTF-8.')
    domains = set()
    ignored = 0
    for line in text.splitlines():
        entry = line.split('#', 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if parts[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            parts = parts[1:]
        if len(parts) != 1:
            ignored += 1
            continue
        try:
            domains.add(domain_name(parts[0]))
        except InvalidInput:
            ignored += 1
    if not domains:
        raise InvalidInput('La lista no contiene dominios válidos. Se admiten dominios y formato hosts, no URL ni reglas Adblock.')
    return sorted(domains), ignored


def import_list(text, kind='block', subdomains=True):
    if kind not in ('block', 'allow') or type(subdomains) is not bool:
        raise InvalidInput('Acción o alcance de subdominios no válido.')
    domains, ignored = parse_list(text)
    db = get_db()
    db.execute('BEGIN IMMEDIATE')
    existing = {r[0] for r in db.execute('SELECT domain FROM rules WHERE kind=?', (kind,))}
    new = [d for d in domains if d not in existing]
    count = db.execute('SELECT count(*) FROM rules').fetchone()[0]
    if count + len(new) > MAX_RULES:
        db.rollback()
        raise InvalidInput('La importación supera el límite de 5000 reglas; no se importó ninguna.')
    try:
        db.executemany('INSERT INTO rules(domain,kind,note,subdomains,active) VALUES (?,?,?,?,1)',
                       [(d, kind, 'Importado desde archivo', subdomains) for d in new])
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        raise InvalidInput('La lista cambió durante la importación. Reintenta.') from None
    current_app.extensions['policy'].refresh()
    return {'added': len(new), 'existing': len(domains) - len(new), 'ignored': ignored}
