"""Cliente de verificación DNS real; no cambia el DNS de Windows."""
import argparse
import json
import time
import dns.message
import dns.query
import dns.rcode

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('domain')
    parser.add_argument('--server', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5353)
    parser.add_argument('--tcp', action='store_true')
    args = parser.parse_args()
    query = dns.message.make_query(args.domain, 'A')
    start = time.perf_counter()
    try:
        method = dns.query.tcp if args.tcp else dns.query.udp
        reply = method(query, args.server, port=args.port, timeout=5)
        print(json.dumps({'domain': args.domain, 'transport': 'TCP' if args.tcp else 'UDP',
                          'rcode': dns.rcode.to_text(reply.rcode()), 'answers': [r.to_text() for r in reply.answer],
                          'milliseconds': round((time.perf_counter() - start) * 1000, 2)}, ensure_ascii=False, indent=2))
    except Exception as error:
        parser.exit(1, 'No se recibió respuesta válida: ' + type(error).__name__ + '. Revisa servidor, puerto, ACL y upstream.\n')
