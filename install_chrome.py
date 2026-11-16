"""Registrar el host para el usuario actual; no instala políticas de Chrome."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from desktop.chrome import HOST_NAME
from desktop.core import atomic_json

ROOT = Path(__file__).resolve().parent
REGISTRY_KEY = 'Software\\Google\\Chrome\\NativeMessagingHosts\\' + HOST_NAME


def extension_id(root=ROOT):
    manifest = json.loads((Path(root) / 'chrome_extension/manifest.json').read_text(encoding='utf-8'))
    digest = hashlib.sha256(base64.b64decode(manifest['key'], validate=True)).hexdigest()[:32]
    return ''.join(chr(ord('a') + int(c, 16)) for c in digest)


def install(root=ROOT):
    import winreg
    root = Path(root).resolve()
    if not (root / '.venv/Scripts/python.exe').is_file():
        raise FileNotFoundError('Primero crea .venv según INICIO_AUTOMATICO.md.')
    manifest = root / 'instance/chrome/native-host.json'
    atomic_json(manifest, {
        'name': HOST_NAME, 'description': 'DNSentinel: sincronización con Chrome',
        'path': str(root / 'chrome_native.cmd'), 'type': 'stdio',
        'allowed_origins': [f'chrome-extension://{extension_id(root)}/'],
    })
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, REGISTRY_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, str(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.exit(1, 'La integración del lanzador requiere Windows.\n')
    if args.uninstall:
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY)
        except FileNotFoundError:
            pass
        print('Registro retirado. Retira también la extensión en chrome://extensions.')
    else:
        install()
        print('Canal nativo registrado para tu usuario. No requiere administrador.')
        print('En chrome://extensions activa Modo de desarrollador y Cargar descomprimida:')
        print(ROOT / 'chrome_extension')
        print('ID esperado: ' + extension_id())
        print('Consulta CHROME.md. Después utiliza los botones habituales del lanzador.')


if __name__ == '__main__':
    main()
