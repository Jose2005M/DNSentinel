"""Inicio conjunto: panel HTTPS local y DNS real UDP/TCP."""
import argparse
import hashlib
import hmac
import logging
from pathlib import Path
import ssl
import os
import threading
import time
from desktop.core import atomic_json, read_json
from dnsentinel import create_app
from dnsentinel.dns_server import DNSService


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web-port', type=int, default=8443)
    parser.add_argument('--dns-port', type=int, default=5353)
    parser.add_argument('--dns-host', default='127.0.0.1')
    parser.add_argument('--allow-network', action='append', help='CIDR autorizado; repetible. Predeterminado: solo loopback.')
    parser.add_argument('--upstream', default='1.1.1.1')
    parser.add_argument('--upstream-port', type=int, default=53)
    parser.add_argument('--cert', default='instance/tls/server-cert.pem')
    parser.add_argument('--key', default='instance/tls/server-key.pem')
    parser.add_argument('--dns-ipv6-loopback', action='store_true', help='Atender también en ::1 para el lanzador Windows.')
    parser.add_argument('--launcher-session', help=argparse.SUPPRESS)
    parser.add_argument('--http', action='store_true', help='Solo desarrollo en loopback, sin TLS.')
    args = parser.parse_args()
    if not 1 <= args.web_port <= 65535:
        parser.error('Puerto del panel fuera del rango 1-65535.')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    session = None
    if args.launcher_session:
        session = Path(args.launcher_session).resolve()
        request = read_json(session / 'request.json')
        if args.http or args.dns_host != '127.0.0.1':
            parser.error('La sesión del lanzador requiere HTTPS y DNS loopback.')
    tls = None
    if not args.http:
        if not Path(args.cert).is_file() or not Path(args.key).is_file():
            parser.error('Primero ejecuta python setup_tls.py y sigue README.md para confiar en la CA local.')
        from cheroot.ssl.builtin import BuiltinSSLAdapter
        tls = BuiltinSSLAdapter(args.cert, args.key)
        tls.context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        app = create_app({'SESSION_COOKIE_SECURE': not args.http, 'LAUNCHER_HEALTH_TOKEN': request['token'] if session else None})
        service = DNSService(app, host=args.dns_host, port=args.dns_port,
                             networks=args.allow_network or ('127.0.0.0/8', '::1/128'),
                             upstream=args.upstream, upstream_port=args.upstream_port,
                             additional_hosts=('::1',) if args.dns_ipv6_loopback else ())
    except Exception as error:
        parser.exit(1, 'No se pudo cargar la configuración: ' + type(error).__name__ + '. Revisa claves, base y opciones.\n')
    try:
        if args.http:
            from waitress import create_server
            web = create_server(app, host='127.0.0.1', port=args.web_port, threads=4,
                                max_request_body_size=1064960, max_request_header_size=16384,
                                channel_timeout=30, connection_limit=50)
        else:
            from cheroot.wsgi import Server
            web = Server(('127.0.0.1', args.web_port), app, numthreads=4, max=8,
                         timeout=30, server_name='localhost')
            web.ssl_adapter = tls
            web.max_request_body_size = 1064960
            web.max_request_header_size = 16384
            web.prepare()
        service.start()
    except (OSError, RuntimeError) as error:
        if 'web' in locals():
            web.close() if args.http else web.stop()
        parser.exit(1, f'No se pudo abrir un puerto: {type(error).__name__}. Prueba --web-port 8444 o --dns-port 5354; revisa IP, permisos y servicios existentes.\n')
    monitor_stop = threading.Event()
    if session:
        policy_file = session / 'chrome-policy.json'
        atomic_json(policy_file, {'rules': app.extensions['policy'].snapshot(), 'time': time.time()})
        pid=os.getpid()
        proof=hmac.new(request['token'].encode(),f'{pid}:{args.web_port}'.encode(),hashlib.sha256).hexdigest()
        atomic_json(session / 'server-ready.json', {'pid':pid,'port':args.web_port,'proof':proof})
        def monitor():
            while not monitor_stop.wait(.5):
                rules = app.extensions['policy'].snapshot()
                try:
                    atomic_json(policy_file, {'rules': rules, 'time': time.time()})
                except OSError:
                    # El controlador detecta la exportación vencida; mantener
                    # disponible la señal de parada y registrar el fallo local.
                    logging.exception('No se pudo publicar la política de Chrome')
                if (session / 'server-stop.json').exists():
                    try:
                        stop = read_json(session / 'server-stop.json')
                        if stop.get('token') != request['token']:
                            continue
                    except (OSError, ValueError):
                        continue
                    # Solo se crea después de restaurar DNS o antes de activarlo.
                    web.stop()
                    return
        threading.Thread(target=monitor, daemon=True, name='dnsentinel-lifecycle').start()
    print(f'Panel: {"http" if args.http else "https"}://localhost:{args.web_port}', flush=True)
    print(f'DNS real UDP/TCP: {args.dns_host}:{args.dns_port}; upstream {args.upstream}:{args.upstream_port}', flush=True)
    print('El lanzador controla el DNS del adaptador y la parada.' if session else 'Ctrl+C detiene ambos servicios. No se modificó el DNS del sistema.', flush=True)
    try:
        web.run() if args.http else web.serve()
    except KeyboardInterrupt:
        logging.info('Deteniendo servicios')
    finally:
        monitor_stop.set()
        service.stop()
        web.close() if args.http else web.stop()


if __name__ == '__main__':
    main()
