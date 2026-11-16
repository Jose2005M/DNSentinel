"""Host Native Messaging de Chrome: únicamente estados y confirmaciones."""
import json
import os
from pathlib import Path
import queue
import struct
import sys
import threading
import time
import uuid

from desktop.chrome import MAX_MESSAGE
from desktop.core import atomic_json, read_json

ROOT = Path(__file__).resolve().parent


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            if not data:
                return None
            raise ValueError('Mensaje nativo incompleto')
        data.extend(part)
    return bytes(data)


def receive(stream):
    header = read_exact(stream, 4)
    if header is None:
        return None
    size = struct.unpack('=I', header)[0]
    if not 0 < size <= 8192:
        raise ValueError('Tamaño de confirmación inválido')
    body = read_exact(stream, size)
    if body is None:
        raise ValueError('Mensaje nativo incompleto')
    message = json.loads(body)
    if not isinstance(message, dict):
        raise ValueError('Mensaje nativo inválido')
    return message


def send(stream, message):
    body = json.dumps(message, separators=(',', ':')).encode('utf-8')
    if len(body) > MAX_MESSAGE:
        raise ValueError('Estado demasiado grande para Chrome')
    stream.write(struct.pack('=I', len(body)) + body)
    stream.flush()


def current_state(directory, now=None):
    try:
        state = read_json(Path(directory) / 'state.json')
        if (now if now is not None else time.time()) < state['expires_at']:
            return {key: state[key] for key in ('revision', 'active', 'rules')}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    # Un lanzador cerrado o detenido no deja reglas persistentes en Chrome.
    return {'revision': 'offline', 'active': False, 'rules': []}


def serve(directory, incoming, outgoing):
    directory = Path(directory)
    client_file = directory / 'clients' / (uuid.uuid4().hex + '.json')
    messages = queue.Queue(maxsize=32)
    def reader():
        try:
            while True:
                message = receive(incoming)
                messages.put(message)
                if message is None:
                    return
        except (OSError, ValueError):
            messages.put(None)
    threading.Thread(target=reader, daemon=True).start()
    revision = None
    sent_at = 0
    acknowledged_at = 0
    acknowledgement = {'revision': None, 'ok': False}
    try:
        while True:
            state = current_state(directory)
            if state['revision'] != revision or time.monotonic() - sent_at >= 1:
                send(outgoing, {'type': 'state', **state})
                revision = state['revision']
                sent_at = time.monotonic()
            try:
                message = messages.get(timeout=.2)
                if message is None:
                    return
                if (message.get('type') == 'ack' and message.get('revision') == revision
                        and type(message.get('ok')) is bool):
                    acknowledgement = {'revision': revision, 'ok': message['ok'],
                                       'error': str(message.get('error', ''))[:500]}
                    acknowledged_at = time.time()
            except queue.Empty:
                pass
            atomic_json(client_file, {**acknowledgement, 'time': acknowledged_at})
    finally:
        client_file.unlink(missing_ok=True)


def main():
    from install_chrome import extension_id
    if len(sys.argv) < 2 or sys.argv[1] != f'chrome-extension://{extension_id(ROOT)}/':
        return 1
    if os.name == 'nt':
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    try:
        serve(ROOT / 'instance/chrome', sys.stdin.buffer, sys.stdout.buffer)
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
