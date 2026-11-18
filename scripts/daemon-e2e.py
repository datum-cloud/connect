#!/usr/bin/env python3
"""Local process E2E: real CLI/daemons/iroh/H3, simulated OAuth/control plane.

No Datum resources are created. Artifacts remain in the printed temp directory.
This is not a live gateway, relay, or VPC certification test.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class Platform(http.server.BaseHTTPRequestHandler):
    objects = {}
    writes = []
    gateway_connectors = []
    lock = threading.Lock()
    accepted_tokens = {'test-access-secret'}
    observed_tokens = set()

    def log_message(self, *_):
        pass

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_api(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.path == '/token':
            return self.reply(200, {'access_token': 'test-access-secret', 'token_type': 'Bearer', 'expires_in': 3600})
        bearer = self.headers.get('Authorization', '').removeprefix('Bearer ')
        if bearer not in self.accepted_tokens:
            return self.reply(401, {})
        self.observed_tokens.add(bearer)
        parts = self.path.strip('/').split('/')
        # The OIDC fixture exercises the CLI's service-catalog activation gate
        # before reaching the daemon. Model an already-active Connect service;
        # activation behavior itself is covered by focused Go tests.
        if parts[-4:] == ['apis', 'services.miloapis.com', 'v1alpha1', 'services']:
            return self.reply(200, {
                'apiVersion': 'services.miloapis.com/v1alpha1',
                'kind': 'ServiceList',
                'metadata': {},
                'items': [{
                    'apiVersion': 'services.miloapis.com/v1alpha1',
                    'kind': 'Service',
                    'metadata': {'name': 'connect-datumapis-com'},
                    'spec': {
                        'displayName': 'Connect',
                        'serviceName': 'connect.datumapis.com',
                        'phase': 'Published',
                        'owner': {'producerProjectRef': {'name': 'provider'}},
                        'enablementPolicy': {'mode': 'GatedByProvider'},
                    },
                }],
            })
        if parts[-4:] == ['apis', 'services.miloapis.com', 'v1alpha1', 'serviceentitlements']:
            return self.reply(200, {
                'apiVersion': 'services.miloapis.com/v1alpha1',
                'kind': 'ServiceEntitlementList',
                'metadata': {},
                'items': [{
                    'apiVersion': 'services.miloapis.com/v1alpha1',
                    'kind': 'ServiceEntitlement',
                    'metadata': {'name': 'connect-datumapis-com', 'resourceVersion': '1'},
                    'spec': {'serviceRef': {'name': 'connect-datumapis-com'}},
                    'status': {
                        'phase': 'Active',
                        'serviceName': 'connect.datumapis.com',
                        'conditions': [{'type': 'Ready', 'status': 'True'}],
                    },
                }],
            })
        if 'connectorclasses' in parts:
            item = {
                'metadata': {'name': 'local-masque', 'generation': 1, 'annotations': {'connect.datum.net/transport': 'masque-v1'}},
                'spec': {'transports': ['masque-v1']},
                'status': {'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 1}]},
            }
            if self.gateway_connectors:
                item['metadata']['annotations']['connect.datum.net/gateway-connectors'] = json.dumps(self.gateway_connectors)
            return self.reply(200, {'items': [item]} if parts[-1] == 'connectorclasses' else item)
        plural_index = next((i for i, x in enumerate(parts) if x in ('connectors', 'connectoradvertisements', 'httpproxies')), None)
        if plural_index is None:
            return self.reply(404, {})
        # NSO and Connect both expose a `connectors` resource, but they live in
        # different API groups and each Connector is independently owned.
        api_indices = [i for i, part in enumerate(parts) if part == 'apis']
        group = parts[api_indices[-1] + 1] if api_indices and api_indices[-1] + 1 < len(parts) else ''
        plural = parts[plural_index]
        name = parts[plural_index+1] if len(parts) > plural_index+1 else ''
        key = (group, plural, name)
        with self.lock:
            if self.command == 'GET':
                if not name:
                    return self.reply(200, {'items': [v for (g, p, _), v in self.objects.items() if g == group and p == plural]})
                return self.reply(200 if key in self.objects else 404, self.objects.get(key, {}))
            value = json.loads(body or b'{}')
            self.writes.append((self.command, plural))
            if self.command == 'POST':
                key = (group, plural, value['metadata']['name'])
                if key in self.objects:
                    return self.reply(409, {})
                value['metadata'].update(uid='uid-' + key[1], resourceVersion='1', generation=1)
                if group == 'connect.datumapis.com' and plural == 'connectors':
                    # The local e2e control plane simulates Connect controller
                    # reconciliation; this is not a controller implementation test.
                    value['status'] = {'conditions': [
                        {'type': 'Accepted', 'status': 'True', 'observedGeneration': 1},
                        {'type': 'Ready', 'status': 'True', 'observedGeneration': 1},
                    ]}
                self.objects[key] = value
                return self.reply(201, value)
            if self.command in ('PUT', 'PATCH'):
                if key not in self.objects:
                    return self.reply(404, {})
                # Exercise spec updates to the Connect-owned API. Controller
                # status remains server-owned and is never written by clients.
                current = self.objects[key]
                if self.command == 'PATCH':
                    for field, patch_value in value.items():
                        if isinstance(patch_value, dict) and isinstance(current.get(field), dict):
                            current[field].update(patch_value)
                        else:
                            current[field] = patch_value
                    value = current
                self.objects[key] = value
                return self.reply(200, value)
            if self.command == 'DELETE':
                self.objects.pop(key, None)
                return self.reply(200, {})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_api


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        data = b'datum-connect-real-iroh-h3-roundtrip\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class UDPOrigin(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(b'udp:' + data, self.client_address)


def server(handler):
    instance = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    return instance


def udp_server():
    instance = socketserver.ThreadingUDPServer(('127.0.0.1', 0), UDPOrigin)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    return instance


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True, type=Path)
    parser.add_argument('--plugin', required=True, type=Path)
    parser.add_argument('--host', type=Path, help='Also validate datumctl dispatch using an installed Connect plugin')
    parser.add_argument('--oidc', action='store_true', help='Run isolated host-session helper enrollment/refresh/restart/logout tests instead of file credentials')
    parser.add_argument('--container-entrypoint', type=Path, help='Test this connectd-container entrypoint with environment-driven serve and dial instead of the CLI')
    args = parser.parse_args()
    if args.container_entrypoint:
        if args.oidc or args.host:
            parser.error('--container-entrypoint does not combine with --oidc or --host')
        return container_e2e(args)
    if args.oidc:
        if args.host:
            parser.error('--oidc uses the direct plugin with a fake helper; do not combine with --host')
        return oidc_e2e(args)
    root = Path(tempfile.mkdtemp(prefix='datum-connect-e2e-'))
    print(f'Artifacts: {root}', flush=True)
    Platform.objects, Platform.writes = {}, []
    platform, origin, denied_origin = server(Platform), server(Origin), server(Origin)
    udp_origin = udp_server()
    procs, logs = {}, []
    ports = {name: free_port() for name in ('alice', 'bob')}
    creds = root / 'credential.json'
    creds.write_text(json.dumps({'type': 'connector', 'project_id': 'demo', 'api_endpoint': f'http://127.0.0.1:{platform.server_port}', 'token_uri': f'http://127.0.0.1:{platform.server_port}/token', 'client_id': 'local-test', 'refresh_token': 'test-refresh-secret'}))
    creds.chmod(0o600)

    def start(name):
        log = (root / f'{name}.log').open('ab')
        logs.append(log)
        procs[name] = subprocess.Popen([str(args.daemon.resolve()), '--repo', str(root/name), '--port', str(ports[name])], stdout=log, stderr=log, env={**os.environ, 'RUST_LOG': 'info,datum_connect_daemon=debug,connect_transport=debug,connect_lib::successor=debug'})
        for _ in range(100):
            if procs[name].poll() is not None:
                raise AssertionError(f'{name} exited; inspect {root/name}.log')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{ports[name]}/v1/health', timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(.1)
        raise AssertionError('daemon did not become healthy')

    def stop(name):
        procs[name].terminate()
        procs[name].wait(timeout=15)

    def token(name):
        return (root/name/'daemon_auth/setup.token').read_text().strip()

    def cli(name, *command, expect=0, bearer=None, project='demo'):
        prefix = [str(args.host.resolve()), 'connect'] if args.host else [str(args.plugin.resolve())]
        # Put the plugin subcommand before flags so datumctl's root parser
        # dispatches it before interpreting plugin-only options.
        result = subprocess.run([*prefix, *command, '--project', project, '--daemon-url', f'http://127.0.0.1:{ports[name]}', '--output', 'json'], cwd=root, env={**os.environ, 'DATUM_CONNECT_TOKEN': bearer or token(name)}, text=True, capture_output=True, timeout=45)
        with (root/'cli.log').open('a') as log:
            log.write(f'{name} {command}\nexit={result.returncode}\n{result.stdout}{result.stderr}\n')
        assert (result.returncode == 0) == (expect == 0), f'{name} {command}: {result.stdout}{result.stderr}; writes={Platform.writes}; resources={list(Platform.objects)}'
        return json.loads(result.stdout) if result.returncode == 0 else result.stderr

    def api(name, method, path, body=None, bearer=None):
        request = urllib.request.Request(f'http://127.0.0.1:{ports[name]}/v1/{path}?project=demo', data=None if body is None else json.dumps(body).encode(), method=method, headers={'Authorization': f'Bearer {bearer or token(name)}', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=45) as response:
            assert response.headers.get('x-request-id'), 'missing diagnostic request ID'
            return json.load(response)

    def roundtrip(port):
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=15) as response:
            assert response.read() == b'datum-connect-real-iroh-h3-roundtrip\n'

    def roundtrip_denied(port):
        try:
            roundtrip(port)
        except (OSError, urllib.error.URLError, TimeoutError):
            return
        raise AssertionError('allowlist denied peer unexpectedly reached the origin')

    def udp_roundtrip(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            for attempt in range(5):
                payload = f'datagram-{attempt}'.encode()
                client.sendto(payload, ('127.0.0.1', port))
                try:
                    reply, _ = client.recvfrom(65535)
                    assert reply == b'udp:' + payload
                    return
                except socket.timeout:
                    continue
        raise AssertionError('UDP datagram did not complete the iroh/H3 roundtrip')

    def delete_connector(name):
        path = f'/apis/connect.datumapis.com/v1alpha1/namespaces/default/connectors/{name}'
        request = urllib.request.Request(
            f'http://127.0.0.1:{platform.server_port}{path}',
            method='DELETE',
            headers={'Authorization': 'Bearer test-access-secret'},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200

    try:
        for name in ports:
            start(name)
        missing = cli('alice', 'serve', 'localhost:800', expect=1)
        assert 'datumctl connect up' in missing and '--credentials-file' in missing
        assert '/v1/up' not in missing and 'HTTP 404' not in missing
        print('PASS first-run error provides CLI setup instructions', flush=True)
        alice = cli('alice', 'up', '--name', 'alice-mac', '--credentials-file', str(creds))
        collision = cli('bob', 'up', '--name', 'alice-mac', '--credentials-file', str(creds), expect=1)
        assert 'already owned' in collision and '--name' in collision
        bob = cli('bob', 'up', '--name', 'bob-mac', '--credentials-file', str(creds))
        akey, bkey = alice['connector']['public_key'], bob['connector']['public_key']
        assert akey != bkey, 'Connector identities must be device-unique'
        other_creds = root/'other-credential.json'
        other_creds.write_text(json.dumps({**json.loads(creds.read_text()), 'project_id': 'other-project'}))
        other_creds.chmod(0o600)
        other = cli('alice', 'up', '--name', 'alice-other', '--credentials-file', str(other_creds), project='other-project')
        assert other['connector']['public_key'] != akey, 'Projects must not share an iroh key'
        cli('alice', 'down', project='other-project')
        service = cli('alice', 'serve', f'127.0.0.1:{origin.server_port}', '--allow', 'bob-mac')
        assert service['ready'] and not service['public']
        assert service['allow'] == [bkey] and service['connector'] == 'alice-mac'
        retry = cli('alice', 'serve', f'127.0.0.1:{origin.server_port}', '--allow', bkey)
        assert retry['id'] == service['id'], 'identical serve retries must reuse intent'
        local = free_port()
        named_dial = cli('bob', 'dial', f'alice-mac:{origin.server_port}', '--bind', str(local))
        assert named_dial['connector'] == akey and named_dial['connector_name'] == 'alice-mac'
        cli('bob', 'dial', f'{akey}:{origin.server_port}', '--bind', str(local))
        roundtrip(local)
        conflict = cli('alice', 'serve', f'localhost:{origin.server_port}', '--allow', bkey, expect=1)
        assert f'Cannot share localhost:{origin.server_port}' in conflict
        assert f'already shared as 127.0.0.1:{origin.server_port}' in conflict
        assert f'unserve 127.0.0.1:{origin.server_port} --project demo' in conflict
        assert 'Retry with --verbose' not in conflict and service['id'] not in conflict
        saved = cli('alice', 'status')['services']
        assert len(saved) == 1 and saved[0]['endpoint'] == service['endpoint']
        assert saved[0]['allow'] == [bkey] and not saved[0]['public']
        roundtrip(local)
        print('PASS conflicting serve names both destinations and preserves the working share', flush=True)
        diagnostics = cli('bob', 'status')['transport']
        assert diagnostics['bytes_sent'] > 0 and diagnostics['bytes_received'] > 0
        assert diagnostics['peers'] and diagnostics['peers'][0]['path'] in ('direct', 'relay')
        print('PASS real CLI -> daemon -> iroh/H3 CONNECT -> TCP origin', flush=True)

        udp_service = cli('alice', 'serve', f'127.0.0.1:{udp_origin.server_address[1]}', '--protocol', 'udp', '--allow', bkey)
        udp_local = free_udp_port()
        cli('bob', 'dial', f'{akey}:{udp_origin.server_address[1]}', '--bind', str(udp_local), '--protocol', 'udp')
        udp_roundtrip(udp_local)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            for sock, message in ((first, b'first-client'), (second, b'second-client')):
                sock.settimeout(15)
                sock.sendto(message, ('127.0.0.1', udp_local))
            assert first.recv(1024) == b'udp:first-client'
            assert second.recv(1024) == b'udp:second-client'
        print('PASS real CLI -> daemon -> iroh/H3 CONNECT-UDP -> UDP origin', flush=True)

        denied_service = cli('alice', 'serve', f'127.0.0.1:{denied_origin.server_port}', '--allow', akey)
        denied_local = free_port()
        cli('bob', 'dial', f'{akey}:{denied_origin.server_port}', '--bind', str(denied_local))
        roundtrip_denied(denied_local)
        cli('bob', 'hangup', str(denied_local))
        cli('alice', 'unserve', denied_service['id'])
        print('PASS service allowlist denies an unlisted Connector', flush=True)

        assert not any(method == 'POST' and kind == 'httpproxies' for method, kind in Platform.writes)
        # The simulated gateway is Bob's real Connector. Test public intent and
        # readiness separately from actual internet ingress (not provided here).
        Platform.gateway_connectors = [bob['connector']['name']]
        public_service = cli('alice', 'serve', f'127.0.0.1:{denied_origin.server_port}', '--public', '--hostname', 'preview.example.test')
        assert public_service['public'] and not public_service['ready'], 'hostname alone must not imply public readiness'
        with Platform.lock:
            proxy = Platform.objects[('networking.datumapis.com', 'httpproxies', public_service['id'])]
            proxy['status'] = {'hostnames': ['preview.example.test'], 'conditions': [
                {'type': kind, 'status': 'True', 'observedGeneration': 1}
                for kind in ('Accepted', 'Programmed', 'CertificatesReady')
            ]}
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if any(s['id'] == public_service['id'] and s['ready'] for s in cli('alice', 'status')['services']):
                break
            time.sleep(1)
        else:
            raise AssertionError('public readiness was not reconciled')
        cli('alice', 'unserve', public_service['id'])
        print('PASS explicit public resource creation and current-generation readiness reconciliation (simulated gateway)', flush=True)
        viewer = api('alice', 'POST', 'tokens', {'role': 'viewer', 'ttl_seconds': 60})
        cli('alice', 'status', bearer=viewer['bearer'])
        cli('alice', 'down', bearer=viewer['bearer'], expect=1)
        api('alice', 'DELETE', 'tokens/' + viewer['token_id'])
        cli('alice', 'status', bearer=viewer['bearer'], expect=1)
        cli('alice', 'join', 'test-vpc', expect=1)
        print('PASS private default, viewer denial, token revocation, unsupported L3 failure', flush=True)
        stop('bob')
        start('bob')
        # Health reports API availability, not completion of asynchronous
        # restart reconciliation. Wait for both restored listeners explicitly.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            resumed = cli('bob', 'status')
            listening = {dial['local_port'] for dial in resumed['dials'] if dial['running']}
            if resumed['running'] and {local, udp_local} <= listening:
                break
            time.sleep(.2)
        else:
            raise AssertionError(f'restored dial listeners did not become ready: {resumed}')
        assert resumed['connector']['public_key'] == bkey
        roundtrip(local)
        print('PASS restart preserves Connector identity and restores dial', flush=True)
        udp_roundtrip(udp_local)
        print('PASS restart restores UDP dial', flush=True)
        cli('bob', 'hangup', str(local))
        cli('bob', 'hangup', str(udp_local))
        cli('alice', 'unserve', service['id'])
        cli('alice', 'unserve', udp_service['id'])
        cli('alice', 'down')
        cli('bob', 'down')
        assert not cli('alice', 'status')['running']
        audit = api('alice', 'GET', 'audit')
        assert audit, 'audit history missing'
        print('PASS cleanup and audit history', flush=True)

        # A deleted Connector must fail closed on the next authorization
        # refresh and must not be silently recreated by reconciliation.
        alice = cli('alice', 'up')
        bob = cli('bob', 'up')
        revoke_service = cli('alice', 'serve', f'127.0.0.1:{origin.server_port}', '--allow', bob['connector']['public_key'])
        revoke_local = free_port()
        cli('bob', 'dial', f"{alice['connector']['public_key']}:{origin.server_port}", '--bind', str(revoke_local))
        roundtrip(revoke_local)
        delete_connector(alice['connector']['name'])
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = cli('alice', 'status')
            if not status['running'] and status.get('last_error_stage') == 'authorization_refresh':
                break
            time.sleep(1)
        else:
            raise AssertionError('deleted Connector did not revoke the running enrollment')
        roundtrip_denied(revoke_local)
        with Platform.lock:
            assert ('connect.datumapis.com', 'connectors', alice['connector']['name']) not in Platform.objects, 'deleted Connector was silently recreated'
        assert not cli('alice', 'status')['services'][0]['running']
        print('PASS control-plane Connector deletion revokes enrollment without recreation', flush=True)
        stop('alice')
        start('alice')
        assert not cli('alice', 'status')['running']
        cli('alice', 'up', expect=1)
        with Platform.lock:
            assert ('connect.datumapis.com', 'connectors', alice['connector']['name']) not in Platform.objects
        print('PASS restart and up cannot recreate a revoked enrollment', flush=True)
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()
        platform.shutdown()
        origin.shutdown()
        denied_origin.shutdown()
        udp_origin.shutdown()
    for name in ports:
        contents = (root/f'{name}.log').read_text()
        for secret in ('test-access-secret', 'test-refresh-secret', token(name)):
            assert secret not in contents, f'secret leaked in {name} logs'
        assert 'request_id' in contents
    print('PASS structured correlation logs contain no test credentials', flush=True)


# Test-only key from `openssl genpkey -algorithm ed25519`, shared with the
# daemon's connector_key unit tests, and its documented public-key derivation.
INJECTED_KEY_PEM = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDGCCjjXq5e7uh1oO5HDUvCKwRBUvsUHabWTv29WE1Af\n-----END PRIVATE KEY-----\n'
INJECTED_PUBLIC_KEY = '03fba577c5a289b42cb771f779faed8273ddc037883fbbb0502584bfc0d504da'


def container_e2e(args):
    """Drive two connectd-container entrypoints through environment variables only."""
    root = Path(tempfile.mkdtemp(prefix='datum-connect-container-e2e-'))
    print(f'Artifacts: {root}', flush=True)
    Platform.objects, Platform.writes = {}, []
    platform, origin = server(Platform), server(Origin)
    creds = root / 'credential.json'
    creds.write_text(json.dumps({'type': 'connector', 'project_id': 'demo', 'api_endpoint': f'http://127.0.0.1:{platform.server_port}', 'token_uri': f'http://127.0.0.1:{platform.server_port}/token', 'client_id': 'local-test', 'refresh_token': 'test-refresh-secret'}))
    creds.chmod(0o400)
    forward, pinned_forward = free_port(), free_port()
    key_file = root / 'secret' / 'connector.pem'
    key_file.parent.mkdir()
    key_file.write_text(INJECTED_KEY_PEM)
    key_file.chmod(0o400)
    other_key = root / 'secret' / 'other.key'
    other_key.write_bytes(os.urandom(32))
    other_key.chmod(0o400)
    environments = {
        # A stable server with persistent state and the default project-wide
        # allow, and an ephemeral dialer that gets a fresh key when recreated.
        'server': {'DATUM_CONNECT_NAME': 'server-pod', 'DATUM_CONNECT_SERVICES': f'127.0.0.1:{origin.server_port}'},
        'client': {'DATUM_CONNECT_EPHEMERAL': 'true', 'DATUM_CONNECT_NAME_HINT': 'Client_VM.example', 'DATUM_CONNECT_DIALS': f'server-pod:{origin.server_port}@0.0.0.0:{forward}'},
        # A diskless forwarder with an injected key and a fixed name, and a
        # server whose allowlist pins that key before the forwarder exists.
        'pinned': {'DATUM_CONNECT_NAME': 'pinned-server', 'DATUM_CONNECT_SERVICES': f'127.0.0.1:{origin.server_port}', 'DATUM_CONNECT_SERVICE_ALLOW': INJECTED_PUBLIC_KEY},
        'forwarder': {'DATUM_CONNECT_NAME': 'forwarder-vm', 'DATUM_CONNECT_CONNECTOR_KEY_FILE': str(root / 'secret' / 'connector.pem'), 'DATUM_CONNECT_DIALS': f'pinned-server:{origin.server_port}@127.0.0.1:{pinned_forward}'},
    }
    for name, env in environments.items():
        env.update({
            'DATUM_CONNECTD_BIN': str(args.daemon.resolve()),
            'DATUM_CONNECT_DIR': str(root / name),
            'DATUM_CONNECT_DAEMON_PORT': str(free_port()),
            'DATUM_CONNECT_CREDENTIALS_FILE': str(creds),
            'DATUM_CONNECT_PROJECT': 'demo',
            'DATUM_CONNECT_RECONCILE_INTERVAL': '2',
            'RUST_LOG': 'info',
        })
    entrypoint = str(args.container_entrypoint.resolve())
    procs, logs = {}, []

    def start(name):
        log = (root / f'{name}.log').open('ab')
        logs.append(log)
        procs[name] = subprocess.Popen(['sh', entrypoint], stdout=log, stderr=log, env={**os.environ, **environments[name]})

    def probe(name):
        return subprocess.run(['sh', entrypoint, 'probe'], env={**os.environ, **environments[name]}, capture_output=True, text=True, timeout=30)

    def wait_ready(name, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert procs[name].poll() is None, f'{name} entrypoint exited; inspect {root}/{name}.log'
            result = probe(name)
            if result.returncode == 0:
                return
            time.sleep(1)
        raise AssertionError(f'{name} probe never passed: {result.stderr}; inspect {root}/{name}.log')

    def status(name):
        token = (root / name / 'daemon_auth/setup.token').read_text().strip()
        request = urllib.request.Request(f"http://127.0.0.1:{environments[name]['DATUM_CONNECT_DAEMON_PORT']}/v1/status?project=demo", headers={'Authorization': f'Bearer {token}'})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def roundtrip(port=None):
        with urllib.request.urlopen(f'http://127.0.0.1:{port or forward}/', timeout=15) as response:
            assert response.read() == b'datum-connect-real-iroh-h3-roundtrip\n'

    def log_lines(name):
        lines = []
        for line in (root / f'{name}.log').read_text().splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if value.get('target') == 'connectd_container':
                lines.append(value['fields'])
        return lines

    try:
        assert probe('server').returncode != 0, 'probe must fail before the daemon starts'
        # The dialer starts first; its dial cannot resolve the server yet.
        start('client')
        time.sleep(8)
        start('server')
        for name in ('client', 'server'):
            wait_ready(name)
        print('PASS entrypoints enroll, serve, and dial from environment variables', flush=True)
        client = status('client')
        assert client['connector']['name'] == 'client-vm-example', client['connector']
        assert [dial['bind_address'] for dial in client['dials']] == ['0.0.0.0']
        roundtrip()
        print('PASS dial bound to 0.0.0.0 forwards to the served origin', flush=True)
        retried = [line for line in log_lines('client') if line['message'] == 'apply_dial' and line.get('result') == 'error']
        assert retried, 'client must retry while the server is not enrolled'
        time.sleep(5)
        ups = [line for line in log_lines('client') if line['message'] == 'apply_up']
        assert [line['result'] for line in ups].count('applied') == 1, ups
        assert ups[-1]['result'] == 'unchanged', 'reapply must not restart a running project'
        print('PASS periodic reapply is idempotent and does not restart the project', flush=True)

        server_key = status('server')['connector']['public_key']
        procs['server'].send_signal(signal.SIGTERM)
        assert procs['server'].wait(timeout=40) == 0, 'SIGTERM must stop the daemon cleanly'
        start('server')
        wait_ready('server')
        assert status('server')['connector']['public_key'] == server_key, 'restart must keep the Connector key'
        ups = [line for line in log_lines('server') if line['message'] == 'apply_up']
        assert [line['result'] for line in ups].count('applied') == 1, 'restart must reuse the saved enrollment'
        wait_ready('client')
        roundtrip()
        print('PASS restart forwards SIGTERM, keeps the Connector identity, and resumes the service', flush=True)

        # Recreate the ephemeral dialer without its state: the hinted name is
        # owned by the previous key, so it enrolls under a suffixed name.
        procs['client'].send_signal(signal.SIGTERM)
        assert procs['client'].wait(timeout=40) == 0
        old_client = client['connector']
        shutil.rmtree(root / 'client')
        start('client')
        wait_ready('client')
        recreated = status('client')['connector']
        assert recreated['public_key'] != old_client['public_key']
        assert recreated['name'].startswith('client-vm-example-') and len(recreated['name']) == len('client-vm-example-') + 6, recreated
        assert any(key[1:] == ('connectors', 'client-vm-example') for key in Platform.objects), 'the previous Connector must not be deleted'
        # The server learns new project devices on its periodic refresh, so a
        # new key may be refused briefly.
        deadline = time.monotonic() + 75
        while True:
            try:
                roundtrip()
                break
            except (OSError, urllib.error.URLError):
                assert time.monotonic() < deadline, 'recreated dialer was never admitted'
                time.sleep(2)
        print('PASS a recreated ephemeral dialer enrolls under a unique name without deleting the old Connector', flush=True)

        daemon = subprocess.run(['pgrep', '-P', str(procs['server'].pid), '-f', 'datum-connectd'], capture_output=True, text=True).stdout.split()
        assert len(daemon) == 1, daemon
        os.kill(int(daemon[0]), signal.SIGKILL)
        assert procs['server'].wait(timeout=20) != 0, 'entrypoint must fail when the daemon dies'
        print('PASS entrypoint exits non-zero when the daemon dies', flush=True)

        start('pinned')
        wait_ready_until = time.monotonic() + 60
        while not [line for line in log_lines('pinned') if line['message'] == 'apply_service']:
            assert time.monotonic() < wait_ready_until, 'pinned server never tried to serve'
            time.sleep(1)
        assert [line['result'] for line in log_lines('pinned') if line['message'] == 'apply_service'][0] == 'error', \
            'an allowlist key must resolve to an existing Connector'
        print('PASS allowlisting a raw key fails until that Connector exists, and the entrypoint retries', flush=True)
        key_stat = key_file.stat()
        identities = []
        for attempt in range(2):
            # Each start uses a fresh, empty state directory.
            shutil.rmtree(root / 'forwarder', ignore_errors=True)
            start('forwarder')
            wait_ready('forwarder')
            wait_ready('pinned')
            roundtrip(pinned_forward)
            identities.append(status('forwarder')['connector'])
            assert not list((root / 'forwarder').rglob('connector.key')), 'an injected key must not be copied into state'
            procs['forwarder'].send_signal(signal.SIGTERM)
            assert procs['forwarder'].wait(timeout=40) == 0
        assert [identity['name'] for identity in identities] == ['forwarder-vm', 'forwarder-vm']
        assert {identity['public_key'] for identity in identities} == {INJECTED_PUBLIC_KEY}
        assert [key[2] for key in Platform.objects if key[1] == 'connectors' and key[2].startswith('forwarder-vm')] == ['forwarder-vm']
        assert (key_file.stat().st_mode, key_file.stat().st_mtime_ns) == (key_stat.st_mode, key_stat.st_mtime_ns)
        logged = [line for line in log_lines('forwarder') if line['message'] == 'apply_up' and line['result'] == 'applied']
        assert len(logged) == 2, 'each fresh state directory enrolls by adopting the same Connector'
        print('PASS an injected key keeps one Connector name and key across fresh state directories', flush=True)

        environments['forwarder']['DATUM_CONNECT_CONNECTOR_KEY_FILE'] = str(other_key)
        start('forwarder')
        deadline = time.monotonic() + 60
        while not any(line['message'] == 'apply_up' and 'connector_key_conflict' in line.get('error', '') for line in log_lines('forwarder')):
            assert time.monotonic() < deadline, f'a different key must conflict with saved state; inspect {root}/forwarder.log'
            time.sleep(1)
        assert probe('forwarder').returncode != 0
        assert status('forwarder')['connector']['public_key'] == INJECTED_PUBLIC_KEY, 'saved identity must not be overwritten'
        print('PASS a different injected key conflicts with saved state instead of replacing it', flush=True)
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()
        platform.shutdown()
        origin.shutdown()
    for name in environments:
        contents = (root / f'{name}.log').read_text()
        token = (root / name / 'daemon_auth/setup.token').read_text().strip()
        for secret in ('test-access-secret', 'test-refresh-secret', token, INJECTED_KEY_PEM.splitlines()[1]):
            assert secret not in contents, f'secret leaked in {name} logs'
    print('PASS entrypoint logs contain no tokens or credentials', flush=True)


def oidc_e2e(args):
    """Exercise real daemon/CLI traffic without touching the user's login."""
    root = Path(tempfile.mkdtemp(prefix='datum-connect-oidc-e2e-'))
    print(f'Artifacts: {root}', flush=True)
    Platform.objects, Platform.writes, Platform.gateway_connectors = {}, [], []
    Platform.observed_tokens = set()
    Platform.accepted_tokens = {'oidc-access-generation-1'}
    platform, origin = server(Platform), server(Origin)
    helper = root / 'datumctl-fixture'
    shutil.copyfile(Path(__file__).parent / 'fixtures/datumctl-oidc-helper.py', helper)
    helper.chmod(0o700)
    helper_state = {'session': 'isolated-test-session', 'generation': 1,
                    'token': 'oidc-access-generation-1', 'expiry_seconds': 5}

    def save_helper():
        target = root / 'helper-state.json'
        temporary = root / 'helper-state.tmp'
        temporary.write_text(json.dumps(helper_state))
        temporary.chmod(0o600)
        temporary.replace(target)

    save_helper()
    clean_env = {key: value for key, value in os.environ.items() if not key.startswith('DATUM_')}
    env = {**clean_env, 'DATUM_CREDENTIALS_HELPER': str(helper.resolve()),
           'TEST_DATUM_HELPER_DIR': str(root),
           'DATUM_SESSION': helper_state['session'],
           'DATUM_API_HOST': f'http://127.0.0.1:{platform.server_port}'}
    ports = {name: free_port() for name in ('alice', 'bob')}
    processes, logs = {}, []

    def start(name):
        log = (root / f'{name}.log').open('ab')
        logs.append(log)
        processes[name] = subprocess.Popen(
            [str(args.daemon.resolve()), '--repo', str(root / name), '--port', str(ports[name])],
            stdout=log, stderr=log,
            env={**clean_env, 'TEST_DATUM_HELPER_DIR': str(root),
                 'DATUM_SESSION': 'must-not-replace-pinned-session',
                 'RUST_LOG': 'info,datum_connect_daemon=debug,connect_lib::successor=debug'})
        for _ in range(100):
            if processes[name].poll() is not None:
                raise AssertionError(f'{name} exited; inspect {root / name}.log')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{ports[name]}/v1/health', timeout=1):
                    return
            except OSError:
                time.sleep(.1)
        raise AssertionError(f'{name} did not become healthy')

    def stop(name):
        processes[name].terminate()
        processes[name].wait(timeout=15)

    def cli(name, *command, expect=0, overrides=None):
        bearer = (root / name / 'daemon_auth/setup.token').read_text().strip()
        result = subprocess.run(
            [str(args.plugin.resolve()), *command, '--project', 'demo', '--daemon-url',
             f'http://127.0.0.1:{ports[name]}', '--output', 'json'],
            env={**env, **(overrides or {}), 'DATUM_CONNECT_TOKEN': bearer},
            text=True, capture_output=True, timeout=45)
        with (root / 'cli.log').open('a') as log:
            log.write(f'{name} {command}\nexit={result.returncode}\n{result.stdout}{result.stderr}\n')
        assert (result.returncode == 0) == (expect == 0), f'{name} {command}: {result.stdout}{result.stderr}'
        return json.loads(result.stdout) if result.returncode == 0 else result.stderr

    def roundtrip(port):
        with urllib.request.urlopen(f'http://127.0.0.1:{port}', timeout=10) as response:
            assert response.read() == b'datum-connect-real-iroh-h3-roundtrip\n'

    def inspect_descriptors():
        for name in ports:
            state = json.loads((root / name / 'daemon/state.json').read_text())
            descriptor = Path(state['projects']['demo']['credentials_file'])
            value = json.loads(descriptor.read_text())
            assert value['type'] == 'datumctl_session', value
            assert value['session'] == 'isolated-test-session', value
            assert value['helper_path'] == str(helper.resolve()), value
            assert value['api_endpoint'] == env['DATUM_API_HOST'], value
            assert 'oidc-access-generation-' not in descriptor.read_text()
            assert not value.get('refresh_token') and not value.get('private_key')

    try:
        for name in ports:
            start(name)
        alice, bob = cli('alice', 'up', '--name', 'alice-mac'), cli('bob', 'up', '--name', 'bob-mac', '--auth', 'oidc')
        akey, bkey = alice['connector']['public_key'], bob['connector']['public_key']
        assert akey != bkey
        inspect_descriptors()
        cli('alice', 'up', overrides={'DATUM_SESSION': 'different-current-context'})
        inspect_descriptors()
        if os.name == 'posix' and os.geteuid() != 0:
            for side, peer in (('alice', 'bob-mac'), ('bob', 'alice-mac')):
                error = cli(side, 'join', 'friend', '--peer', peer, '--allow-ping', '--allow-tcp', '8080', expect=1)
                assert 'administrator approval' in error and 'never elevate' in error
            aplan = cli('alice', 'doctor')['networking']['saved_attachments'][0]
            bplan = cli('bob', 'doctor')['networking']['saved_attachments'][0]
            assert aplan['peer'] == bkey and bplan['peer'] == akey
            assert aplan['assigned_address'] == bplan['peer_address']
            assert aplan['peer_address'] == bplan['assigned_address']
            assert not cli('alice', 'status')['networks'] and not cli('bob', 'status')['networks']
            print('PASS real CLI/daemon peer setup pins discovered keys, derives symmetric addresses, and never elevates automation', flush=True)
        service = cli('alice', 'serve', f'127.0.0.1:{origin.server_port}', '--allow', bkey)
        local = free_port()
        cli('bob', 'dial', f'{akey}:{origin.server_port}', '--bind', str(local))
        roundtrip(local)
        print('PASS OIDC enrollment uses pinned helper session, secret-free descriptor, and real iroh/H3 TCP', flush=True)

        # Leave generation 1 accepted so only expiry, not a forced HTTP 401,
        # explains why the daemon obtains and uses generation 2.
        helper_state.update(generation=2, token='oidc-access-generation-2')
        Platform.accepted_tokens.add(helper_state['token'])
        save_helper()
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            cli('bob', 'ping', akey)
            if 'oidc-access-generation-2' in Platform.observed_tokens:
                break
            time.sleep(1)
        else:
            raise AssertionError('expired helper credential was not refreshed')
        roundtrip(local)
        print('PASS helper token expires and refreshes to a new access token without reconnecting the CLI', flush=True)

        stop('bob')
        start('bob')
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            resumed = cli('bob', 'status')
            if resumed['running'] and resumed['dials'] and resumed['dials'][0]['running']:
                break
            time.sleep(.2)
        assert resumed['connector']['public_key'] == bkey and resumed['running']
        if os.name == 'posix' and os.geteuid() != 0:
            assert resumed['networking']['saved_attachments'][0]['peer'] == akey
            assert not resumed['networks'], 'saved peer configuration must not auto-join after restart'
        roundtrip(local)
        inspect_descriptors()
        calls = [json.loads(line) for line in (root / 'helper-calls.jsonl').read_text().splitlines()]
        expected_helper_args = ['auth', 'get-token', '--session', 'isolated-test-session']
        assert calls and all(
            (call['args'] == expected_helper_args + ['--output', 'client.authentication.k8s.io/v1'])
            or (len(call['args']) == 4 and call['args'][:3] == expected_helper_args[:3])
            for call in calls)
        print('PASS daemon restart pins the original host session and restores the existing Connector and dial', flush=True)

        helper_state['logged_out'] = True
        save_helper()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            statuses = [cli(name, 'status') for name in ports]
            if all(not state['running'] and state.get('last_error_stage') == 'authorization_refresh' for state in statuses):
                break
            time.sleep(1)
        else:
            raise AssertionError('host logout did not fail closed after periodic authorization refresh')
        try:
            roundtrip(local)
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        else:
            raise AssertionError('forwarding survived host session logout')
        print('PASS helper logout stops networking on the next authorization refresh', flush=True)
        stop('bob')
        start('bob')
        assert not cli('bob', 'status')['running']
        cli('bob', 'up', '--auth', 'stored', expect=1)
        print('PASS logged-out restart and stored-auth up fail closed without silently changing sessions', flush=True)
    finally:
        for proc in processes.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()
        platform.shutdown()
        origin.shutdown()
    for name in ports:
        for path in (root / name).rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                assert b'oidc-access-generation-' not in data, f'access token persisted in {path}'
    for path in [root / 'cli.log', *(root / f'{name}.log' for name in ports)]:
        assert 'oidc-access-generation-' not in path.read_text(), f'access token leaked in {path}'
    print('PASS OIDC access tokens never appear in daemon state or diagnostic logs', flush=True)


if __name__ == '__main__':
    main()
