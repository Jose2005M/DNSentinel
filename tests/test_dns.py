"""Pruebas reales de sockets contra un upstream controlado, sin Internet."""
import io
import secrets
import socket
import socketserver
import struct
import threading
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rrset
import pytest

from dnsentinel import create_app
from dnsentinel.crypto_store import decrypt_row, reveal, seal
from dnsentinel.db import get_db, record_event
from dnsentinel.dns_server import Buckets, DNSService
from dnsentinel.lists import parse_list, import_list
from dnsentinel.validation import InvalidInput


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture
def app(tmp_path):
    return create_app({'TESTING': True, 'DATABASE': str(tmp_path/'dns.sqlite3'),
                       'RATE_KEY': secrets.token_bytes(32), 'DATA_KEY': secrets.token_bytes(32)})


@pytest.fixture
def upstream():
    seen = []
    def response(wire, tcp):
        query = dns.message.from_wire(wire)
        name = query.question[0].name.to_text()
        seen.append((name, tcp))
        answer = dns.message.make_response(query)
        answer.flags |= dns.flags.RA | dns.flags.AD
        if name == 'truncated.test.' and not tcp:
            answer.flags |= dns.flags.TC
        elif name == 'absent.test.':
            answer.set_rcode(dns.rcode.NXDOMAIN)
        else:
            answer.answer.append(dns.rrset.from_text(name, 60, 'IN', 'A', '203.0.113.9'))
        return answer.to_wire()
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            wire, sock = self.request
            sock.sendto(response(wire, False), self.client_address)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            length = self.request.recv(2)
            if len(length) != 2:
                return
            size = struct.unpack('!H', length)[0]
            data = b''
            while len(data) < size:
                piece = self.request.recv(size-len(data))
                if not piece:
                    return
                data += piece
            wire = response(data, True)
            self.request.sendall(struct.pack('!H', len(wire)) + wire)
    tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), TCP)
    udp = socketserver.ThreadingUDPServer(('127.0.0.1', tcp.server_address[1]), UDP)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (tcp, udp)]
    for thread in threads:
        thread.start()
    yield tcp.server_address[1], seen
    for server in (tcp, udp):
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(3)


@pytest.fixture
def service(app, upstream):
    with app.app_context():
        import_list('malware.test', 'block', True)
        import_list('safe.malware.test', 'allow', False)
    server = DNSService(app, port=free_port(), upstream='127.0.0.1', upstream_port=upstream[0], timeout=.3)
    server.start()
    yield server
    server.stop()
    assert not server._thread.is_alive()
    assert server.status['log_errors'] == 0


def ask(service, name, tcp=False, kind='A'):
    query = dns.message.make_query(name, kind)
    result = (dns.query.tcp if tcp else dns.query.udp)(query, '127.0.0.1', port=service.port, timeout=2)
    assert result.id == query.id
    assert result.question == query.question
    assert not result.flags & dns.flags.AD
    return result


@pytest.mark.parametrize('tcp', [False, True])
def test_actual_block_allow_and_label_boundaries(service, upstream, tcp):
    for name in ['malware.test', 'sub.malware.test', 'other.safe.malware.test']:
        assert ask(service, name, tcp).rcode() == dns.rcode.REFUSED
    for name in ['safe.malware.test', 'notmalware.test']:
        result = ask(service, name, tcp)
        assert result.rcode() == dns.rcode.NOERROR
        assert result.answer[0][0].address == '203.0.113.9'
    assert not any(name in ('malware.test.', 'sub.malware.test.') for name, _ in upstream[1])


def test_udp_falls_back_to_tcp_and_nxdomain_is_preserved(service, upstream):
    assert ask(service, 'truncated.test').answer
    assert ('truncated.test.', False) in upstream[1]
    assert ('truncated.test.', True) in upstream[1]
    assert ask(service, 'absent.test').rcode() == dns.rcode.NXDOMAIN


@pytest.mark.parametrize('kind', ['ANY', 'AXFR', 'IXFR'])
def test_refuses_transfer_and_any(service, kind):
    assert ask(service, 'normal.test', kind=kind).rcode() == dns.rcode.REFUSED


def test_update_rule_applies_without_restart(service, app):
    assert ask(service, 'new.test').rcode() == dns.rcode.NOERROR
    with app.app_context():
        import_list('new.test', 'block', True)
    assert ask(service, 'new.test').rcode() == dns.rcode.REFUSED


def test_real_log_encrypted_and_client_pseudonymous(service, app):
    ask(service, 'malware.test')
    service.stop()  # drena el registro antes de leer
    with app.app_context():
        row = get_db().execute('SELECT * FROM events').fetchone()
        assert row['domain'].startswith('enc:v1:')
        assert 'malware.test' not in str(dict(row))
        data = decrypt_row(row, 'events')
        assert data['domain'] == 'malware.test' and data['mode'] == 'real'
        assert data['client'] != '127.0.0.1' and len(data['client']) == 20


def test_upstream_unavailable_returns_servfail(app):
    service = DNSService(app, port=free_port(), upstream='127.0.0.1', upstream_port=free_port(), timeout=.1)
    service.start()
    try:
        assert ask(service, 'normal.test').rcode() == dns.rcode.SERVFAIL
    finally:
        service.stop()
    with app.app_context():
        row = get_db().execute('SELECT * FROM events').fetchone()
        assert decrypt_row(row, 'events')['decision'] == 'failed'


def test_acl_denies_real_udp_client(app):
    service = DNSService(app, port=free_port(), networks=('192.0.2.0/24',))
    service.start()
    try:
        with pytest.raises(dns.exception.Timeout):
            dns.query.udp(dns.message.make_query('example.test', 'A'), '127.0.0.1', port=service.port, timeout=.1)
        assert service.status['denied'] >= 1
    finally:
        service.stop()


def test_malformed_packets_and_multiple_questions_do_not_crash(service):
    malformed = b'\x12\x34\x01\x00\x00\x01' + b'\x00'*6
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.sendto(malformed, ('127.0.0.1', service.port))
        assert dns.message.from_wire(sock.recv(4096)).rcode() == dns.rcode.FORMERR
    query = dns.message.make_query('a.test', 'A')
    query.question.extend(dns.message.make_query('b.test', 'A').question)
    answer = dns.query.udp(query, '127.0.0.1', port=service.port, timeout=1)
    assert answer.rcode() == dns.rcode.FORMERR
    assert ask(service, 'malware.test').rcode() == dns.rcode.REFUSED


def test_encryption_detects_tampering_and_wrong_field(app):
    with app.app_context():
        value = seal('sensitive.test', 'events.domain')
        assert reveal(value, 'events.domain') == 'sensitive.test'
        with pytest.raises(Exception):
            reveal(value, 'audit.actor')
        with pytest.raises(Exception):
            reveal(value[:-5]+'AAAAA', 'events.domain')


def test_migrates_v02_plaintext_and_rejects_wrong_key(app):
    with app.app_context():
        db = get_db()
        db.execute('INSERT INTO events(time,domain,type,transport,decision,reason,created) VALUES (?,?,?,?,?,?,?)',
                   ('2026-11-10', 'legacy.test', 'A', 'UDP', 'allowed', 'old', time.time()))
        db.commit()
    config = {'TESTING': True, 'DATABASE': app.config['DATABASE'], 'RATE_KEY': app.config['RATE_KEY'], 'DATA_KEY': app.config['DATA_KEY']}
    restored = create_app(config)
    with restored.app_context():
        row = get_db().execute('SELECT * FROM events').fetchone()
        assert decrypt_row(row, 'events')['domain'] == 'legacy.test'
    with pytest.raises(Exception):
        create_app({**config, 'DATA_KEY': secrets.token_bytes(32)})


def test_list_parser_validation_and_duplicates(app):
    domains, ignored = parse_list('# test\n0.0.0.0 malware.test\nMALWARE.TEST\nexample.test\nhttps://bad.test\n127.0.0.1 localhost\n')
    assert set(domains) == {'malware.test', 'example.test'} and ignored == 2
    with app.app_context():
        result = import_list('a.test\nb.test', 'block', True)
        assert result['added'] == 2
        result = import_list('a.test\nc.test', 'block', True)
        assert result['added'] == 1 and result['existing'] == 1
        with pytest.raises(InvalidInput):
            import_list('\n'.join(f'x{i}.test' for i in range(5000)), 'block', True)
        assert get_db().execute('SELECT count(*) FROM rules').fetchone()[0] == 3


def test_no_universal_acl_or_self_forwarder(app):
    with pytest.raises(ValueError):
        DNSService(app, networks=('0.0.0.0/0',))
    with pytest.raises(ValueError):
        DNSService(app, port=5353, upstream='127.0.0.1', upstream_port=5353)


def test_rate_bucket_and_bounded_memory():
    bucket = Buckets(rate=0, burst=2)
    assert bucket.allow('client') and bucket.allow('client')
    assert not bucket.allow('client')
    for i in range(5000):
        bucket.allow(str(i))
    assert len(bucket.clients) == 4096
