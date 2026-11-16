"""Servidor DNS UDP/TCP acotado a clientes autorizados de un laboratorio."""
import asyncio
from collections import OrderedDict
import hashlib
import hmac
import ipaddress
import logging
import struct
import threading
import time

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .db import record_event, purge_expired


class Buckets:
    def __init__(self, rate=30, burst=60):
        self.rate, self.burst = rate, burst
        self.clients = OrderedDict()

    def allow(self, key):
        now = time.monotonic()
        tokens, last = self.clients.pop(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1
        self.clients[key] = (tokens - 1 if allowed else tokens, now)
        if len(self.clients) > 4096:
            self.clients.popitem(last=False)
        return allowed


class DNSService:
    def __init__(self, app, host='127.0.0.1', port=5353, networks=('127.0.0.0/8', '::1/128'),
                 upstream='1.1.1.1', upstream_port=53, timeout=2.0, additional_hosts=()):
        self.app, self.host, self.port = app, host, port
        self.hosts = (host, *additional_hosts)
        for address in self.hosts:
            ipaddress.ip_address(address)
        self.networks = [ipaddress.ip_network(n, strict=True) for n in networks]
        if any(n.prefixlen == 0 for n in self.networks):
            raise ValueError('No se permiten redes universales /0.')
        self.upstream = str(ipaddress.ip_address(upstream))
        ipaddress.ip_address(host)
        if not 1 <= port <= 65535 or not 1 <= upstream_port <= 65535:
            raise ValueError('Puerto fuera del rango 1-65535.')
        if port == upstream_port and (upstream == host or ipaddress.ip_address(upstream).is_loopback):
            raise ValueError('El upstream no puede apuntar al mismo servicio DNS.')
        self.upstream_port, self.timeout = upstream_port, timeout
        self.status = {'running': False, 'hosts': list(self.hosts), 'host': host, 'port': port, 'upstream': upstream,
                       'upstream_port': upstream_port, 'allowed_networks': list(networks),
                       'processed': 0, 'denied': 0, 'log_dropped': 0, 'log_errors': 0}
        app.config['DNS_STATUS'] = self.status
        self.buckets, self.global_bucket = Buckets(), Buckets(rate=100, burst=200)
        self.active = 0
        self.connections = 0
        self._thread = None
        self._ready = threading.Event()
        self._error = None

    def authorized(self, address):
        try:
            ip = ipaddress.ip_address(address)
            return any(ip in network for network in self.networks)
        except ValueError:
            return False

    def admitted(self, address):
        ok = (self.authorized(address) and self.buckets.allow(address) and
              self.global_bucket.allow('all') and self.active < 64)
        if not ok:
            self.status['denied'] += 1
        return ok

    def pseudonym(self, address):
        return hmac.new(self.app.config['RATE_KEY'], address.encode(), hashlib.sha256).hexdigest()[:20]

    def error_response(self, request, code):
        result = dns.message.make_response(request)
        result.flags |= dns.flags.RA
        result.set_rcode(code)
        return result

    async def answer(self, wire, address, transport):
        try:
            request = dns.message.from_wire(wire, ignore_trailing=False)
        except (dns.exception.DNSException, ValueError):
            if len(wire) < 12:
                return None
            reply = dns.message.Message(id=int.from_bytes(wire[:2], 'big'))
            reply.flags = dns.flags.QR | dns.flags.RA
            reply.set_rcode(dns.rcode.FORMERR)
            return reply.to_wire()
        if request.flags & dns.flags.QR:
            return None  # nunca responder a respuestas recibidas
        if request.opcode() != dns.opcode.QUERY or len(request.question) != 1:
            return self.error_response(request, dns.rcode.FORMERR).to_wire()
        question = request.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        record_type = dns.rdatatype.to_text(question.rdtype)
        token = self.app.config.get('LAUNCHER_HEALTH_TOKEN')
        if token and name == 'dnsentinel-health.invalid' and question.rdtype == dns.rdatatype.TXT and question.rdclass == dns.rdataclass.IN:
            response = self.error_response(request, dns.rcode.NOERROR)
            response.answer.append(dns.rrset.from_text(question.name, 0, 'IN', 'TXT', '"' + token + '"'))
            return response.to_wire()

        if question.rdclass != dns.rdataclass.IN or question.rdtype in (
                dns.rdatatype.AXFR, dns.rdatatype.IXFR, dns.rdatatype.ANY):
            result = {'decision': 'blocked', 'reason': 'Tipo de consulta no permitido en el laboratorio'}
            response = self.error_response(request, dns.rcode.REFUSED)
        else:
            result = self.app.extensions['policy'].evaluate(name)
            if result['decision'] == 'blocked':
                response = self.error_response(request, dns.rcode.REFUSED)
            else:
                # Identificador aleatorio nuevo para el salto upstream. No reenviar secciones arbitrarias.
                query = dns.message.make_query(question.name, question.rdtype, question.rdclass,
                                               use_edns=True, payload=1232,
                                               want_dnssec=bool(request.ednsflags & dns.flags.DO))
                if request.flags & dns.flags.CD:
                    query.flags |= dns.flags.CD
                try:
                    if transport == 'TCP':
                        response = await dns.asyncquery.tcp(query, self.upstream, port=self.upstream_port,
                                                           timeout=self.timeout)
                    else:
                        response, _ = await dns.asyncquery.udp_with_fallback(
                            query, self.upstream, port=self.upstream_port, timeout=self.timeout)
                    response.id = request.id
                    response.question = request.question
                    response.flags &= ~dns.flags.AD  # no se realiza validación DNSSEC propia
                    if response.rcode() == dns.rcode.SERVFAIL:
                        result = {'decision': 'failed', 'reason': 'El servidor upstream devolvió SERVFAIL'}
                except (dns.exception.DNSException, OSError, ValueError):
                    response = self.error_response(request, dns.rcode.SERVFAIL)
                    result = {'decision': 'failed', 'reason': 'Fallo o tiempo de espera del servidor upstream'}
        # Restaurar el bit RD del cliente sin afirmar autoridad ni validación local.
        response.flags = (response.flags & ~dns.flags.RD) | (request.flags & dns.flags.RD)
        self.status['processed'] += 1
        try:
            self.log_queue.put_nowait((name, record_type, transport, result['decision'], result['reason'], self.pseudonym(address)))
        except asyncio.QueueFull:
            self.status['log_dropped'] += 1
        size = min(max(request.payload, 512), 1232) if transport == 'UDP' else 65535
        return response.to_wire(max_size=size, prefer_truncation=True)

    async def handle_udp(self, data, address, transport=None):
        self.active += 1
        try:
            response = await self.answer(data, address[0], 'UDP')
            if response:
                (transport or self.udp).sendto(response, address)
        except Exception:  # la tarea no debe dejar de atender otros clientes
            logging.getLogger('dnsentinel.dns').error('Fallo interno en consulta UDP; sin datos de la consulta')
        finally:
            self.active -= 1

    async def handle_tcp(self, reader, writer):
        address = writer.get_extra_info('peername')[0]
        if not self.authorized(address) or self.connections >= 32:
            self.status['denied'] += 1
            writer.close()
            return
        self.connections += 1
        try:
            for _ in range(20):
                length = struct.unpack('!H', await asyncio.wait_for(reader.readexactly(2), 5))[0]
                if not 12 <= length <= 4096 or not self.admitted(address):
                    break
                data = await asyncio.wait_for(reader.readexactly(length), 5)
                self.active += 1
                try:
                    response = await self.answer(data, address, 'TCP')
                finally:
                    self.active -= 1
                if response is None:
                    break
                writer.write(struct.pack('!H', len(response)) + response)
                await asyncio.wait_for(writer.drain(), 5)
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError, OSError):
            logging.getLogger('dnsentinel.dns').debug('Cliente TCP desconectado o lento')
        except Exception:
            logging.getLogger('dnsentinel.dns').error('Fallo interno en consulta TCP; sin datos de la consulta')
        finally:
            self.connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                logging.getLogger('dnsentinel.dns').debug('Conexión TCP ya cerrada')

    def write_log(self, args):
        with self.app.app_context():
            record_event(*args, mode='real')

    async def log_worker(self):
        while True:
            item = await self.log_queue.get()
            try:
                await asyncio.to_thread(self.write_log, item)
            except Exception:
                self.status['log_errors'] += 1
                logging.getLogger('dnsentinel.dns').error('No se pudo guardar el evento DNS cifrado')
            finally:
                self.log_queue.task_done()

    async def maintenance(self):
        while True:
            await asyncio.sleep(86400)
            try:
                await asyncio.to_thread(self.purge)
            except Exception:
                logging.getLogger('dnsentinel.dns').error('Falló el mantenimiento de registros')

    def purge(self):
        with self.app.app_context():
            purge_expired()

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        self.log_queue = asyncio.Queue(maxsize=256)
        owner = self

        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, address):
                if 12 <= len(data) <= 4096 and owner.admitted(address[0]):
                    # Reservar antes de programar la tarea para limitar incluso una ráfaga.
                    owner.active += 1
                    async def dispatch():
                        owner.active -= 1
                        await owner.handle_udp(data, address, self.transport)
                    asyncio.create_task(dispatch())

        self.tcp_list, self.udp_list = [], []
        try:
            for host in self.hosts:
                tcp = await asyncio.start_server(self.handle_tcp, host, self.port, limit=8192)
                self.tcp_list.append(tcp)
                udp, _ = await self.loop.create_datagram_endpoint(UDP, local_addr=(host, self.port))
                self.udp_list.append(udp)
            self.tcp, self.udp = self.tcp_list[0], self.udp_list[0]
        except Exception:
            for udp in self.udp_list:
                udp.close()
            for tcp in self.tcp_list:
                tcp.close()
                await tcp.wait_closed()
            raise
        worker = asyncio.create_task(self.log_worker())
        maintenance = asyncio.create_task(self.maintenance())
        self.status['running'] = True
        self._ready.set()
        try:
            await self.stop_event.wait()
        finally:
            self.status['running'] = False
            for udp in self.udp_list:
                udp.close()
            for tcp in self.tcp_list:
                tcp.close()
                await tcp.wait_closed()
            # Drenar tareas de clientes antes de cerrar el registro.
            current = asyncio.current_task()
            clients = [t for t in asyncio.all_tasks() if t not in (current, worker, maintenance)]
            for task in clients:
                task.cancel()
            await asyncio.gather(*clients, return_exceptions=True)
            await self.log_queue.join()
            worker.cancel()
            maintenance.cancel()
            await asyncio.gather(worker, maintenance, return_exceptions=True)

    def start(self):
        def target():
            try:
                asyncio.run(self.run())
            except Exception as error:
                self._error = error
                self._ready.set()
        self._thread = threading.Thread(target=target, daemon=True, name='dnsentinel-dns')
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError('El servicio DNS no inició a tiempo.')
        if self._error:
            raise RuntimeError('No se pudo abrir el puerto DNS. Revisa el puerto, la IP y los permisos.') from self._error

    def stop(self):
        if self._thread and self._thread.is_alive():
            self.loop.call_soon_threadsafe(self.stop_event.set)
            self._thread.join(timeout=15)
