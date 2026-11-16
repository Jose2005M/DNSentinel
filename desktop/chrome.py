"""Canal local del lanzador con la extensión, sin puertos ni API web."""
import json
import os
from pathlib import Path
import threading
import time
import uuid

from .core import ProtectionError, atomic_json, read_json

HOST_NAME = 'org.dnsentinel.chrome'
LEASE_SECONDS = 4
CLIENT_SECONDS = 4
MAX_MESSAGE = 1024 * 1024


class ChromeController:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        # Una segunda ventana no puede desactivar la extensión de la primera.
        self._file = (self.directory / 'controller.lock').open('a+b')
        self._file.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._file.close()
            raise ProtectionError('Ya hay otro lanzador conectado a Chrome. Usa esa ventana.') from None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._policy = None
        self._rules = []
        self._active = False
        self._revision = uuid.uuid4().hex
        self.error = None
        self._thread = threading.Thread(target=self._run, daemon=True, name='chrome-controller')
        self._thread.start()

    def _publish(self):
        atomic_json(self.directory / 'state.json', {
            'revision': self._revision, 'active': self._active, 'rules': self._rules,
            'expires_at': time.time() + LEASE_SECONDS,
        })

    def enable(self, session):
        policy = Path(session) / 'chrome-policy.json'
        rules = self._read_policy(policy)
        if len(json.dumps(rules).encode('utf-8')) > MAX_MESSAGE - 4096:
            raise ProtectionError('La lista supera el tamaño del canal de Chrome.')
        with self._lock:
            self._policy, self._rules, self._active = policy, rules, True
            self._revision = uuid.uuid4().hex
            self._publish()
            self.error = None
        self.wait()

    @staticmethod
    def _read_policy(path):
        policy = read_json(path)
        if not 0 <= time.time() - policy['time'] < LEASE_SECONDS:
            raise ProtectionError('El servidor dejó de actualizar las reglas de Chrome.')
        return policy['rules']

    def disable(self):
        with self._lock:
            if not self._active:
                self._publish()
                self.error = None
                return
            self._policy, self._rules, self._active = None, [], False
            self._revision = uuid.uuid4().hex
            self._publish()
            self.error = None

    def clients(self):
        result = []
        for path in (self.directory / 'clients').glob('*.json'):
            try:
                client = read_json(path)
                if 0 <= time.time() - client['time'] < CLIENT_SECONDS:
                    result.append(client)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return result

    def synchronized(self):
        with self._lock:
            clients = self.clients()
            return bool(clients) and not self.error and all(
                c.get('revision') == self._revision and c.get('ok') is True for c in clients)

    def wait(self, timeout=12, allow_absent=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.synchronized():
                return True
            if allow_absent and not self.clients():
                return False
            errors = [c.get('error') for c in self.clients() if c.get('revision') == self._revision and c.get('error')]
            if errors or self.error:
                raise ProtectionError('Chrome no confirmó las reglas: ' + str(self.error or errors[0]))
            time.sleep(.1)
        raise ProtectionError('Chrome no confirmó la sincronización. Abre Chrome e instala/activa la extensión siguiendo CHROME.md.')

    def _run(self):
        while not self._stop.is_set():
            try:
                with self._lock:
                    if self._policy:
                        rules = self._read_policy(self._policy)
                        if rules != self._rules:
                            if len(json.dumps(rules).encode('utf-8')) > MAX_MESSAGE - 4096:
                                raise ProtectionError('La lista supera el tamaño del canal de Chrome.')
                            self._rules = rules
                            self._revision = uuid.uuid4().hex
                    self._publish()
                    self.error = None
            except (OSError, ValueError, KeyError, ProtectionError) as error:
                self.error = str(error)
            self._stop.wait(.25)

    def close(self):
        self.disable()
        self._stop.set()
        self._thread.join(timeout=2)
        self._file.close()
