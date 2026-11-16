"""Estado transaccional y restauración, independiente de la interfaz de Windows."""
from contextlib import nullcontext
import ipaddress
import json
import os
from pathlib import Path
import secrets
import time
import uuid


class ProtectionError(RuntimeError):
    pass


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        with temp.open('x', encoding='utf-8') as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
            file.flush()
            os.fsync(file.fileno())
        # Windows puede negar el reemplazo mientras otro proceso lee el JSON.
        # El lector cierra enseguida; conservar siempre el último archivo completo.
        for attempt in range(30):
            try:
                os.replace(temp, path)
                break
            except PermissionError:
                if os.name != 'nt' or attempt == 29:
                    raise
                time.sleep(.01)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path):
    with Path(path).open(encoding='utf-8') as file:
        return json.load(file)


def family_config(source, addresses, family):
    if source not in ('automatic', 'static') or not isinstance(addresses, list):
        raise ProtectionError('Respaldo DNS no válido.')
    addresses = [str(ipaddress.ip_address(a)) for a in addresses]
    if any(ipaddress.ip_address(a).version != family for a in addresses):
        raise ProtectionError('Familia de dirección incorrecta.')
    if (source == 'static' and not addresses) or (source == 'automatic' and addresses):
        raise ProtectionError('Modo DNS incompatible con sus direcciones.')
    return {'source': source, 'addresses': addresses}


def managed_config(family):
    return family_config('static', ['127.0.0.1' if family == 4 else '::1'], family)


def validate_backup(state):
    if state.get('schema') != 1 or state.get('phase') not in ('saved','active','restoring','restore_failed','restored'):
        raise ProtectionError('No se reconoce el respaldo de red.')
    uuid.UUID(state['adapter']['guid'])
    uuid.UUID(state['run_id'])
    original = state['original']
    if '4' not in original or set(original) - {'4','6'}:
        raise ProtectionError('Familias DNS del respaldo no válidas.')
    for family, config in original.items():
        family_config(config['source'], config['addresses'], int(family))
    return state


class NetworkProtection:
    def __init__(self, backend, state_file, lock_factory=nullcontext):
        self.backend = backend
        self.state_file = Path(state_file)
        self.lock_factory = lock_factory

    def save(self, state):
        atomic_json(self.state_file, state)
        if hasattr(self.backend, 'secure_backup'):
            self.backend.secure_backup(self.state_file)

    def state(self):
        return validate_backup(read_json(self.state_file)) if self.state_file.exists() else None

    def prepare(self, guid, run_id):
        with self.lock_factory():
            old = self.state()
            if old and old['phase'] != 'restored':
                raise ProtectionError('Hay un respaldo pendiente. Usa Restaurar DNS antes de activar otra sesión.')
            adapter = self.backend.adapter(str(uuid.UUID(guid)))
            original = {}
            for family in ([4,6] if adapter['ipv6'] else [4]):
                config = self.backend.snapshot(adapter, family)
                config = family_config(config['source'], config['addresses'], family)
                if any(ipaddress.ip_address(a).is_loopback for a in config['addresses']):
                    raise ProtectionError('Tu DNS original ya apunta a loopback. Restaura primero la configuración previa al cambio manual a 127.0.0.1; no podemos adivinarla.')
                original[str(family)] = config
            state = {'schema':1,'phase':'saved','run_id':str(uuid.UUID(run_id)),
                     'adapter':adapter,'original':original,'saved_at':time.time()}
            self.save(state)
            return state

    def activate(self, run_id):
        with self.lock_factory():
            state = self.state()
            if not state or state['run_id'] != run_id or state['phase'] != 'saved':
                raise ProtectionError('La sesión no coincide con el respaldo guardado.')
            adapter = self.backend.adapter(state['adapter']['guid'])
            # No sobrescribir una configuración que cambió desde el respaldo.
            for family, original in state['original'].items():
                if self.backend.snapshot(adapter, int(family)) != original:
                    raise ProtectionError('El DNS cambió mientras se preparaba la protección. No se modificó.')
            for family in state['original']:
                self.backend.apply(adapter, int(family), managed_config(int(family)))
                if self.backend.snapshot(adapter, int(family)) != managed_config(int(family)):
                    raise ProtectionError('Windows no confirmó la configuración DNS solicitada.')
            state['phase'] = 'active'
            self.save(state)
            self.backend.flush()
            return state

    def restore(self, run_id=None):
        with self.lock_factory():
            state = self.state()
            if not state or state['phase'] == 'restored':
                return state
            if run_id is not None and state['run_id'] != run_id:
                raise ProtectionError('El respaldo pertenece a otra sesión; no se modificó.')
            adapter = self.backend.adapter(state['adapter']['guid'])
            state['phase'] = 'restoring'
            self.save(state)
            errors = []
            for family, original in state['original'].items():
                try:
                    number = int(family)
                    current = self.backend.snapshot(adapter, number)
                    if current == original:
                        continue
                    # Aceptar estados parciales de una restauración de servidores estáticos.
                    partial = (current['source'] == 'static' and original['source'] == 'static'
                               and current['addresses'] == original['addresses'][:len(current['addresses'])])
                    if current != managed_config(number) and not partial:
                        raise ProtectionError('El DNS fue cambiado por otra herramienta. Revisa el adaptador antes de restaurar.')
                    self.backend.apply(adapter, number, original)
                    if self.backend.snapshot(adapter, number) != original:
                        raise ProtectionError('Windows no confirmó la restauración.')
                except Exception as error:
                    errors.append(str(error))
            state['phase'] = 'restore_failed' if errors else 'restored'
            self.save(state)
            if errors:
                raise ProtectionError('No se pudo completar la restauración: ' + '; '.join(errors))
            self.backend.flush()
            return state
