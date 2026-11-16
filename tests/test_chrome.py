"""Protocolo nativo y ciclos del controlador, sin tocar el DNS ni el registro."""
import io
import json
from pathlib import Path
import struct
import threading
import time

import pytest

from chrome_native import current_state, receive, send, serve
from desktop.chrome import ChromeController
from desktop.core import ProtectionError, atomic_json, read_json
from install_chrome import extension_id


def eventually(check, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.02)
    raise AssertionError('No se observó el estado esperado')


def test_native_frames_partial_reads_unicode_and_limits():
    stream = io.BytesIO()
    send(stream, {'type': 'ack', 'error': 'extensión', 'ok': False})
    class Fragmented(io.BytesIO):
        def read(self, size):return super().read(min(size, 2))
    assert receive(Fragmented(stream.getvalue()))['error'] == 'extensión'
    assert receive(io.BytesIO()) is None
    for data in [b'a', struct.pack('=I', 8193), struct.pack('=I', 2) + b'{',
                 struct.pack('=I', 2) + b'[]']:
        with pytest.raises(ValueError):receive(io.BytesIO(data))


def test_crashed_launcher_lease_removes_rules(tmp_path):
    state = {'revision': 'one', 'active': True, 'rules': [], 'expires_at': 104}
    atomic_json(tmp_path/'state.json', state)
    assert current_state(tmp_path, now=103)['active'] is True
    assert current_state(tmp_path, now=104) == {'revision': 'offline', 'active': False, 'rules': []}
    (tmp_path/'state.json').write_text('{', encoding='utf-8')
    assert current_state(tmp_path)['active'] is False


def test_expired_server_policy_is_rejected(tmp_path):
    path = tmp_path/'chrome-policy.json'
    atomic_json(path, {'rules': [], 'time': time.time()-10})
    with pytest.raises(ProtectionError, match='dejó de actualizar'):
        ChromeController._read_policy(path)


def test_cycles_require_current_ack_and_live_client(tmp_path):
    policy = tmp_path/'session/chrome-policy.json'
    atomic_json(policy, {'rules': [{'domain': 'example.com', 'kind': 'block', 'subdomains': 1}], 'time': time.time()})
    controller = ChromeController(tmp_path/'bridge')
    stop = threading.Event()
    observed = []
    def chrome():
        while not stop.wait(.02):
            state = current_state(controller.directory)
            observed.append(state)
            atomic_json(controller.directory/'clients/test.json', {
                'revision': state['revision'], 'ok': True, 'time': time.time()})
    client = threading.Thread(target=chrome)
    client.start()
    try:
        for _ in range(3):
            controller.enable(policy.parent)
            assert controller.synchronized()
            controller.disable()
            controller.wait(timeout=2)
            assert not read_json(controller.directory/'state.json')['active']
        controller.enable(policy.parent)
        old = read_json(controller.directory/'state.json')['revision']
        atomic_json(policy, {'rules': [{'domain': 'other.test', 'kind': 'block', 'subdomains': 0}], 'time': time.time()})
        eventually(lambda: read_json(controller.directory/'state.json')['revision'] != old)
        controller.wait(timeout=2)
        assert read_json(controller.directory/'state.json')['rules'][0]['domain'] == 'other.test'
        stop.set();client.join(timeout=2)
        atomic_json(controller.directory/'clients/test.json', {'revision': old, 'ok': True, 'time': time.time()})
        assert not controller.synchronized()
        atomic_json(controller.directory/'clients/test.json', {'revision': old, 'ok': True, 'time': 0})
        assert not controller.synchronized()
        with pytest.raises(ProtectionError, match='Chrome no confirmó'):
            controller.wait(timeout=.1)
    finally:
        stop.set();client.join(timeout=2);controller.close()
    assert any(s['active'] for s in observed) and any(not s['active'] for s in observed)


def test_second_launcher_cannot_clear_first(tmp_path):
    first = ChromeController(tmp_path)
    try:
        with pytest.raises(ProtectionError):ChromeController(tmp_path)
    finally:first.close()


def test_failed_extension_ack_is_not_success(tmp_path):
    controller = ChromeController(tmp_path)
    try:
        eventually(lambda: (tmp_path/'state.json').exists())
        state = read_json(tmp_path/'state.json')
        atomic_json(tmp_path/'clients/test.json', {'revision': state['revision'], 'ok': False,
                                                  'error': 'Límite de reglas', 'time': time.time()})
        with pytest.raises(ProtectionError, match='Límite de reglas'):controller.wait(timeout=.5)
    finally:controller.close()


def test_stable_extension_id_is_valid_and_uses_only_public_key():
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    import base64
    import re
    root = Path(__file__).resolve().parents[1]
    assert re.fullmatch('[a-p]{32}', extension_id(root))
    manifest = json.loads((root/'chrome_extension/manifest.json').read_text(encoding='utf-8'))
    assert load_der_public_key(base64.b64decode(manifest['key'])).key_size == 2048
    assert manifest['incognito'] == 'not_allowed'


def test_native_host_round_trip_and_connection_cleanup(tmp_path):
    import os
    read_fd, write_fd = os.pipe()
    output_read, output_write = os.pipe()
    incoming = os.fdopen(read_fd, 'rb', buffering=0)
    outgoing = os.fdopen(output_write, 'wb', buffering=0)
    chrome_write = os.fdopen(write_fd, 'wb', buffering=0)
    chrome_read = os.fdopen(output_read, 'rb', buffering=0)
    atomic_json(tmp_path/'state.json', {'revision': 'cycle', 'active': True, 'rules': [],
                                      'expires_at': time.time()+10})
    host = threading.Thread(target=serve, args=(tmp_path, incoming, outgoing), daemon=True)
    host.start()
    try:
        assert receive(chrome_read) == {'type': 'state', 'revision': 'cycle', 'active': True, 'rules': []}
        send(chrome_write, {'type': 'ack', 'revision': 'stale', 'ok': True})
        eventually(lambda: bool(list((tmp_path/'clients').glob('*.json'))))
        assert not read_json(next((tmp_path/'clients').glob('*.json')))['ok']
        send(chrome_write, {'type': 'ack', 'revision': 'cycle', 'ok': True})
        eventually(lambda: read_json(next((tmp_path/'clients').glob('*.json')))['ok'])
        atomic_json(tmp_path/'state.json', {'revision': 'stop', 'active': False, 'rules': [],
                                          'expires_at': time.time()+10})
        assert receive(chrome_read)['revision'] == 'stop'
    finally:
        chrome_write.close();host.join(timeout=3)
        incoming.close();outgoing.close();chrome_read.close()
    assert not host.is_alive() and not list((tmp_path/'clients').glob('*.json'))
