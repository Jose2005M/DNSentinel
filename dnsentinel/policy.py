"""Instantánea inmutable de reglas activas; compartida por web y servicio DNS."""
import threading
from .db import get_db


class Policy:
    def __init__(self):
        self._lock = threading.Lock()
        self._rules = ()

    def refresh(self):
        with self._lock:
            rows = get_db().execute('SELECT domain,kind,subdomains FROM rules WHERE active=1 ORDER BY id').fetchall()
            self._rules = tuple(dict(r) for r in rows)

    def evaluate(self, domain):
        domain = domain.lower().removesuffix('.')
        with self._lock:
            rules = self._rules
        # Subdominios por límites de etiqueta; no coincide "notmalware.test".
        labels = domain.split('.')
        suffixes = {'.'.join(labels[i:]) for i in range(1, len(labels))}
        matches = [r for r in rules if r['domain'] == domain or
                   (r['subdomains'] and r['domain'] in suffixes)]
        for kind, decision, prefix in [('allow', 'allowed', 'Excepción: '), ('block', 'blocked', 'Bloqueo: ')]:
            rule = next((r for r in matches if r['kind'] == kind), None)
            if rule:
                return {'decision': decision, 'reason': prefix + rule['domain']}
        return {'decision': 'allowed', 'reason': 'Sin coincidencia en las reglas activas'}

    def snapshot(self):
        with self._lock:
            return [dict(rule) for rule in self._rules]
