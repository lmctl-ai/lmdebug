#!/usr/bin/env python3
"""Bounded request-segment supervisor; timings come only from lmssl."""
from __future__ import annotations
import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

MAX_BODY = 1048576
MAX_OUTPUT = 1048576
SEGMENTS = {
    'dns_us': 'resolver/cache lookup call; not DNS packet latency',
    'tcp_connect_us': 'numeric-address connect call; not wire RTT',
    'tls_handshake_us': 'TLS connect including identity/trust validation',
    'greeting_wait_us': 'server-first greeting first-byte wait before request',
    'greeting_transfer_us': 'server-first greeting read interval before request',
    'request_write_us': 'complete stream write; not peer ACK',
    'ttfb_us': 'request write end to first positive read(1) return',
    'transfer_us': 'first to last positive response read; raw headers/body bytes',
    'eof_observation_us': 'last positive response read to EOF return',
    'close_call_us': 'local close API only; not full peer disconnect',
}


def bounded_run(argv, timeout=3.0):
    """Bound combined output and lifetime, including DNS in a subprocess."""
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    active = list(buffers)
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while active and time.monotonic() < deadline:
            for stream in select.select(active, [], [], min(.05, max(0, deadline-time.monotonic())))[0]:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    active.remove(stream)
                    continue
                available = MAX_OUTPUT - sum(map(len, buffers.values()))
                buffers[stream].extend(chunk[:available])
                if len(chunk) > available:
                    failure = 'output_limit'
                    break
            if failure:
                break
        if failure is None:
            try:
                child.wait(timeout=max(.001, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = 'timeout'
        if active and time.monotonic() >= deadline:
            failure = 'timeout'
    finally:
        if failure or child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        for stream in buffers:
            stream.close()
    code = 124 if failure == 'timeout' else 125 if failure else child.returncode
    output = buffers[child.stdout].decode('utf-8', errors='replace')
    error = buffers[child.stderr].decode('utf-8', errors='replace')
    if failure:
        error = (error + '\nsupervisor: ' + failure)[-MAX_OUTPUT:]
    return subprocess.CompletedProcess(argv, code, output, error)


def certificate(directory):
    result = bounded_run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                          '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                          '-addext', 'basicConstraints=critical,CA:TRUE',
                          '-keyout', str(directory/'key.pem'), '-out', str(directory/'cert.pem')], 8)
    if result.returncode:
        raise RuntimeError('local CA/certificate generation failed: ' + result.stderr)
    os.chmod(directory/'key.pem', 0o600)


class Fixture:
    def __init__(self, mode, case, directory, exchange_mode):
        self.mode, self.case, self.directory, self.exchange_mode = mode, case, directory, exchange_mode
        self.error = None
        self.received = bytearray()
        self.stop = threading.Event()
        self.active = None
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, name='segment-fixture')
        self.thread.start()

    def serve(self):
        conn = None
        try:
            while not self.stop.is_set():
                try:
                    conn, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if conn is None:
                return
            self.active = conn
            conn.settimeout(3)
            if self.mode == 'local-https':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(self.directory/'cert.pem'), str(self.directory/'key.pem'))
                context.set_alpn_protocols(['http/1.1'])
                conn = context.wrap_socket(conn, server_side=True)
                self.active = conn
            if self.exchange_mode == 'server-first':
                self.stop.wait(.03)
                conn.sendall(b'G')
                self.stop.wait(.04)
                conn.sendall(b'REETING')
            while not self.stop.is_set() and len(self.received) < MAX_BODY:
                data = conn.recv(4096)
                if not data:
                    break
                self.received.extend(data)
                if self.mode == 'local-https' and b'\r\n\r\n' in self.received:
                    break
                if self.mode == 'local-tcp' and len(self.received) >= 4:
                    break
            if self.case == 'stall':
                self.stop.wait(25)
                return
            self.stop.wait(.03)
            if self.case == 'empty':
                payload = b''
            elif self.case == 'one-byte':
                payload = b'H' if self.mode == 'local-https' else b'P'
            elif self.mode == 'local-https':
                payload = b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 15\r\n\r\nsegment-fixture'
                if self.case == 'early-eof':
                    payload = payload[:-5]
            else:
                payload = b'PONG' if self.case == 'early-eof' else b'PONG-tail'
            if payload:
                conn.sendall(payload[:1])
                self.stop.wait(.04)
                if len(payload) > 1:
                    conn.sendall(payload[1:])
            if isinstance(conn, ssl.SSLSocket):
                # Send close_notify so the client's EOF is a clean TLS EOF.
                conn = conn.unwrap()
                self.active = conn
        except (OSError, ssl.SSLError) as exc:
            # A rejected certificate, a response cap or timeout can close the
            # client early. Preserve that as fixture evidence, not request proof.
            self.error = str(exc)
        finally:
            if conn:
                conn.close()
            self.active = None

    def close(self):
        self.stop.set()
        if self.active:
            try:
                self.active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=4)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError('fixture thread did not terminate')


def observed(program, *args):
    try:
        cp = bounded_run([program, *args])
        return {'returncode': cp.returncode, 'stdout': cp.stdout, 'stderr': cp.stderr}
    except OSError as exc:
        return {'returncode': None, 'stdout': '', 'stderr': str(exc)}


def inventory(args):
    versions, hashes = {}, {}
    for name, program in [('lmssl', args.host_program), ('lmdebug', args.lmdebug)]:
        if not program:
            versions[name], hashes[name] = 'unavailable', None
            continue
        version = observed(program, '--version')
        versions[name] = version['stdout'].strip() if version['returncode'] == 0 else version
        schema = observed(program, '--dsl-schema', '--json')
        if schema['returncode'] == 0:
            try:
                json.loads(schema['stdout'])
                hashes[name] = hashlib.sha256(schema['stdout'].encode()).hexdigest()
            except ValueError:
                hashes[name] = None
        else:
            hashes[name] = None
    context = {'collection': 'outside measured intervals'}
    for key, verb in [('ifaddrs', 'ifaddrs'), ('routes', 'route')]:
        result = observed(args.lmdebug, verb) if args.lmdebug else {'returncode': None, 'stderr': 'lmdebug unavailable', 'stdout': ''}
        try:
            result['data'] = json.loads(result.pop('stdout')) if result['returncode'] == 0 else None
        except ValueError:
            result['data'] = None
            result['error'] = 'invalid context JSON'
        context[key] = result
    return versions, hashes, context


def validate(measured, args):
    if not measured.get('complete'):
        return 'incomplete_measurement'
    if measured.get('cap_exhausted'):
        return 'cap_exhausted'
    if not args.mode.endswith('https'):
        if args.expected_length >= 0 and measured.get('response_bytes') != args.expected_length:
            return 'early_eof'
        if args.expected_length < 0 and not measured.get('eof'):
            return 'missing_eof'
        return None
    payload = bytes.fromhex(measured.get('response_hex', ''))
    split = payload.find(b'\r\n\r\n')
    if split < 0 or split+4 > 65536:
        return 'missing_or_oversized_http_headers'
    head, body = payload[:split], payload[split+4:]
    lines = head.split(b'\r\n')
    if not re.fullmatch(rb'HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?', lines[0]):
        return 'invalid_http_status'
    headers = {}
    for line in lines[1:]:
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x09\x20-\x7e\x80-\xff]*", line):
            return 'invalid_http_header'
        key, value = line.split(b':', 1)
        headers.setdefault(key.lower(), []).append(value.strip())
    if b'content-length' in headers:
        lengths = headers[b'content-length']
        if len(lengths) != 1 or not re.fullmatch(rb'[0-9]+', lengths[0]):
            return 'invalid_content_length'
        if b'transfer-encoding' in headers:
            return 'ambiguous_http_framing'
        if len(body) != int(lengths[0]):
            return 'content_length_mismatch'
    if b'transfer-encoding' in headers:
        measured['http_framing'] = 'chunked_wire_bytes_not_decoded_or_validated'
    else:
        measured['http_framing'] = 'content_length_validated' if b'content-length' in headers else 'close_delimited'
    measured['http_status'] = int(lines[0].split(b' ')[1])
    measured['location'] = headers.get(b'location', [b''])[0].decode('latin1')
    if not measured.get('eof'):
        return 'missing_http_eof'
    return None


def artifacts(args, output, measured, cp, fixture, started, info, error=None):
    try:
        validation = validate(measured, args)
    except (TypeError, ValueError) as exc:
        validation = 'invalid_measurement: ' + str(exc)
    error = error or validation
    status = 'ok' if cp.returncode == 0 and error is None else 'error'
    measured.pop('response_hex', None)
    for key in [*SEGMENTS, 'total_us', 'first_byte_us', 'last_byte_us']:
        if measured.get(key, -1) < 0:
            measured[key] = None
    accounted = sum(measured.get(key) or 0 for key in SEGMENTS)
    total = measured.get('total_us')
    versions, hashes, context = info
    report = {
        'format_version': 1, 'kind': 'segment_timing', 'mode': args.mode, 'status': status,
        'request': getattr(args, 'request_metadata', None),
        'classification': 'timeout' if cp.returncode == 124 else error,
        'measured': measured,
        'segments': {'accounted_us': accounted, 'total_us': total,
                     'residual_us': total-accounted if total is not None else None,
                     'close_call_kind': 'tls_shutdown_attempt' if args.mode.endswith('https') else 'tcp_local_close',
                     'disconnect_us': None, 'disconnect_status': 'not_observed_without_capture'},
        'context': context, 'schema_hashes': hashes, 'versions': versions,
        'supervisor': {'elapsed_us': int((time.monotonic()-started)*1000000), 'deadline_s': args.timeout,
                       'network_required': args.mode.startswith('remote-'), 'preflight_lookup': getattr(args, 'preflight', None)},
        'host': {'program': args.host_program, 'returncode': cp.returncode, 'stderr': cp.stderr[-4096:], 'validation_error': error},
        'fixture': {'port': fixture.port, 'received_bytes': len(fixture.received), 'error': fixture.error,
                    'thread_alive': fixture.thread.is_alive()} if fixture else None,
        'limits': {'response_bytes': args.cap, 'header_bytes': 65536, 'measurement_clock': 'ssl.monotonic_us',
                   'supervisor_clock': 'diagnostic-only; never a segment'},
    }
    (output/'checkpoint.json').write_text(json.dumps(measured)+'\n')
    (output/'report.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    (output/'host.stdout').write_text(cp.stdout)
    (output/'host.stderr').write_text(cp.stderr)
    with (output/'segments.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['segment', 'duration_us', 'duration_ms', 'measurement'])
        for key, explanation in SEGMENTS.items():
            value = measured[key]
            writer.writerow([key[:-3], '' if value is None else value, '' if value is None else f'{value/1000:.3f}', explanation])
    rows = ['| Segment | ms | Measurement |', '| --- | ---: | --- |']
    for key, explanation in SEGMENTS.items():
        value = measured[key]
        rows.append(f'| {key[:-3]} | {"missing" if value is None else f"{value/1000:.3f}"} | {explanation} |')
    (output/'report.md').write_text(f'# Request segment timings\n\nStatus: {status}; classification: {report["classification"]}.\n\n'+
        '\n'.join(rows)+'\n\nClock differences stay inside this lmssl process. No capture timestamps are aligned.\n'
        'TLS close is one shutdown attempt; disconnect_us=null (not_observed_without_capture).\n'
        'Raw bytes include HTTP headers/body; chunked data is not decoded. No DB query CPU time is measured.\n'+
        f'Total: {total} us; accounted: {accounted} us; residual: {report["segments"]["residual_us"]} us.\n')
    print(f'{args.mode}: {status}; artifacts={output}')
    return 0 if status == 'ok' else cp.returncode or 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=['local-https', 'local-tcp', 'remote-https', 'remote-tcp'])
    parser.add_argument('--mode', dest='mode_option')
    parser.add_argument('--host-program', required=True)
    parser.add_argument('--bytecode', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--lmdebug', default=shutil.which('lmdebug'))
    parser.add_argument('--url', default='https://lmctl.com/')
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--request-hex')
    parser.add_argument('--expected-length', type=int)
    parser.add_argument('--cap', type=int, default=MAX_BODY)
    parser.add_argument('--exchange-mode', choices=['client-first', 'server-first'], default='client-first')
    parser.add_argument('--greeting-length', type=int, default=0)
    parser.add_argument('--timeout', type=float, default=20)
    parser.add_argument('--fixture-case', choices=['normal', 'one-byte', 'empty', 'early-eof', 'cap', 'stall', 'server-first', 'bad-cert', 'bad-host'], default='normal')
    args = parser.parse_args(argv)
    args.mode = args.mode_option or args.mode
    if args.mode not in ['local-https', 'local-tcp', 'remote-https', 'remote-tcp']:
        parser.error('valid mode is required')
    if not math.isfinite(args.timeout) or not .1 <= args.timeout <= 20:
        parser.error('timeout must be between 0.1 and 20 seconds')
    if not 1 <= args.cap <= MAX_BODY or not 0 <= args.greeting_length <= MAX_BODY:
        parser.error('response/greeting bounds must be within 1 MiB')
    if args.exchange_mode == 'server-first' and args.greeting_length <= 0:
        parser.error('server-first requires positive --greeting-length')
    if args.expected_length is not None and not 1 <= args.expected_length <= MAX_BODY:
        parser.error('expected length must be between 1 and 1048576')
    if args.mode == 'remote-tcp' and (not args.host or args.port is None or args.request_hex is None or args.expected_length is None):
        parser.error('remote TCP requires --host --port --request-hex --expected-length; protocol bytes are deliberate')
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error('port outside 1..65535')
    if args.request_hex is not None and (not re.fullmatch(r'(?:[0-9a-fA-F]{2})*', args.request_hex) or len(args.request_hex) > 2*65536):
        parser.error('request must be valid hex, at most 64 KiB')
    args.expected_length = args.expected_length if args.expected_length is not None else -1
    if args.mode == 'local-tcp' and args.fixture_case == 'early-eof':
        args.expected_length = 9
    if args.fixture_case == 'server-first':
        args.exchange_mode, args.greeting_length = 'server-first', 8
    started = time.monotonic()
    os.umask(0o077)
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink():
        parser.error('output directory cannot be a symlink')
    os.chmod(output, 0o700)
    # Reserve a new checkpoint for this attempt; never reuse stale completion.
    checkpoint = output/'checkpoint.json'
    checkpoint.unlink(missing_ok=True)
    info = inventory(args)
    fixture = None
    measured = {}
    cp = subprocess.CompletedProcess([], 1, '', '')
    error = None
    with tempfile.TemporaryDirectory(prefix='lmssl-segment-') as temp:
        directory = Path(temp)
        try:
            trust = ''
            if args.mode.startswith('local-'):
                if args.mode.endswith('https'):
                    certificate(directory)
                    trust = str(directory/'cert.pem')
                fixture = Fixture(args.mode, args.fixture_case, directory, args.exchange_mode)
                hostname, selected, port = 'localhost', '127.0.0.1', fixture.port
                if args.fixture_case == 'bad-cert':
                    trust = ''
                if args.fixture_case == 'bad-host':
                    hostname = '127.0.0.1'  # CA has DNS:localhost only.
            else:
                if args.mode.endswith('https'):
                    url = urlsplit(args.url)
                    if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None or any(ord(c)<33 or ord(c)==127 for c in args.url) or url.fragment:
                        parser.error('URL must be HTTPS without userinfo, control/space characters or fragment')
                    hostname, port = url.hostname, url.port or 443
                    authority = '['+hostname+']' if ':' in hostname else hostname
                    if port != 443:
                        authority += ':'+str(port)
                    target = url.path or '/'
                    if url.query:
                        target += '?'+url.query
                    args.request_hex = ('GET '+target+' HTTP/1.1\r\nHost: '+authority+'\r\nConnection: close\r\n\r\n').encode('ascii').hex()
                else:
                    hostname, port = args.host, args.port
                # getaddrinfo can block independently of socket timeouts. Bound
                # this untimed selection lookup, then measure resolve again in DSL.
                resolver = bounded_run([sys.executable, '-c',
                    'import socket,json,sys; print(json.dumps([x[4][0] for x in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)]))',
                    hostname, str(port)], args.timeout)
                if resolver.returncode:
                    raise RuntimeError('untimed DNS selection failed: '+resolver.stderr)
                candidates = json.loads(resolver.stdout)
                selected = str(ipaddress.ip_address(candidates[0]))
                args.preflight = {'hostname': hostname, 'selected_ip': selected, 'cache': 'may be warm; timed lookup repeats and confirms selection'}
            request = args.request_hex if args.request_hex is not None else ('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode().hex() if args.mode.endswith('https') else '50494e47')
            args.request_metadata = {'hostname': hostname, 'port': port, 'selected_ip': selected,
                                     'url': args.url if args.mode == 'remote-https' else None,
                                     'exchange_mode': args.exchange_mode, 'expected_length': args.expected_length,
                                     'request_contents': 'omitted'}
            child = [args.host_program, '--dsl', args.bytecode, str(checkpoint), hostname, selected, str(port), request,
                     str(args.cap), str(args.expected_length), args.exchange_mode, str(args.greeting_length), trust,
                     str(args.mode.endswith('https')).lower()]
            cp = bounded_run(child, args.timeout)
            if checkpoint.exists():
                if checkpoint.stat().st_size > 2*MAX_BODY+65536:
                    raise ValueError('checkpoint exceeds bounded response size')
                measured = json.loads(checkpoint.read_text())
        except (OSError, ValueError, RuntimeError) as exc:
            error = str(exc)
        finally:
            if fixture:
                fixture.close()
    return artifacts(args, output, measured, cp, fixture, started, info, error)


if __name__ == '__main__':
    raise SystemExit(main())
