"""Sonda de identidad del DNS del lanzador, por ambos transportes y familias."""
import hmac
import dns.message
import dns.query
import dns.rcode

HEALTH_NAME = 'dnsentinel-health.invalid'


def healthy(token, port=53, ipv6=True, timeout=1):
    try:
        for address in (['127.0.0.1','::1'] if ipv6 else ['127.0.0.1']):
            for method in (dns.query.udp, dns.query.tcp):
                response = method(dns.message.make_query(HEALTH_NAME, 'TXT'), address, port=port, timeout=timeout)
                if response.rcode() != dns.rcode.NOERROR or not response.answer:
                    return False
                data = response.answer[0][0]
                if not hasattr(data, 'strings') or not hmac.compare_digest(b''.join(data.strings), token.encode()):
                    return False
        return True
    except Exception:
        return False
