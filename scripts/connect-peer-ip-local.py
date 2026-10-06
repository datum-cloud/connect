#!/usr/bin/env python3
"""Two-daemon CONNECT-IP lab, with no gateway in the data path.

Only Cloud/OAuth are simulated. All Docker networks/containers are disposable,
uniquely labeled, and isolated from the host. --ipv6 disables non-loopback IPv4.
--relay-urls explicitly allows internet egress for real relay enrollment.
"""
import argparse
import http.server
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid

CONNECT = Path(__file__).resolve().parents[1]
WORKSPACE = CONNECT.parent
SCRIPT = "/workspace/connect/scripts/connect-peer-ip-local.py"
GATEWAY_SCRIPT = "/workspace/iroh-gateway/scripts/connect-ip-local.py"
BODY = b"direct-daemon-connect-ip-http\n"


def endpoint_ip_addresses(connector):
    """Extract direct IP hints from the serialized Connect Connector endpoint."""
    raw_endpoint = connector.get("spec", {}).get("endpoint", "")
    try:
        endpoint = json.loads(raw_endpoint) if isinstance(raw_endpoint, str) else raw_endpoint
    except json.JSONDecodeError:
        return set()

    addresses = set()

    def visit(value):
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str):
            candidates = [value]
            if value.startswith("[") and "]" in value:
                candidates.append(value[1:value.index("]")])
            if ":" in value:
                candidates.append(value.rsplit(":", 1)[0].strip("[]"))
            for candidate in candidates:
                try:
                    addresses.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    pass

    visit(endpoint)
    return addresses


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture():
    base = module(CONNECT / "scripts/daemon-e2e.py", "cloud_fixture")

    class Platform(base.Platform):
        def handle_api(self):
            if self.path == "/fixture/peers":
                if self.command == "POST":
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                    with self.lock:
                        for value in body:
                            self.objects[("connectors", value["metadata"]["name"])] = value
                    return self.reply(200, {})
                return self.reply(200, [v for (kind, _), v in self.objects.items() if kind == "connectors"])
            if self.path == "/fixture/revoke":
                self.accepted_tokens.clear()
                return self.reply(200, {})
            if self.path == "/fixture/restore":
                self.accepted_tokens.add("test-access-secret")
                return self.reply(200, {})
            return super().handle_api()

        do_GET = do_POST = do_PUT = do_DELETE = handle_api

    http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Platform).serve_forever()


def origin(address):
    ipv6 = ":" in address
    family = socket.AF_INET6 if ipv6 else socket.AF_INET

    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            with open("/lab/received.log", "a") as log:
                log.write(json.dumps({"source": self.client_address[0], "port": sock.getsockname()[1], "length": len(data)}) + "\n")
            sock.sendto(data, self.client_address)

    class HTTPServer(http.server.ThreadingHTTPServer):
        address_family = family

    class UDPServer(socketserver.ThreadingUDPServer):
        address_family = family

    # Denied ports have real listeners: rejection cannot be a closed-port artifact.
    for port in (8080, 8081, 8082):
        server = HTTPServer((address, port), HTTP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    for port in (5353, 5354, 5355):
        server = UDPServer((address, port), UDP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


def udp_probe(address, port, denied=False):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    maximum = 1232 if family == socket.AF_INET6 else 1252
    for data in ([b"denied"] if denied else [b"peer-ip", b"", bytes(range(256)) * 4, bytes(maximum)]):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            # QUIC DATAGRAM is unreliable. A newly probed path may drop packets
            # during bounded MTU validation; retry at the application layer.
            for attempt in range(5):
                sock.sendto(data, (address, port))
                try:
                    received, _ = sock.recvfrom(65535)
                except socket.timeout:
                    if denied:
                        return
                    if attempt == 4:
                        raise
                    continue
                assert not denied, "unapproved UDP port replied"
                assert received == data, "UDP data changed"
                break


def run_lab(args):
    docker = ["docker", "--context", args.docker_context]
    tag = "connect-ip-" + uuid.uuid4().hex[:10]
    target = CONNECT / "target"
    target.mkdir(exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=tag + "-peer-", dir=target))
    print(f"Artifacts: {artifacts}", flush=True)
    binaries = args.binaries.resolve()
    for name in ("datumctl", "datumctl-connect", "datum-connect-daemon"):
        if not (binaries / name).is_file():
            raise RuntimeError(f"Missing {binaries / name}; use --build")
    if args.helper and not (binaries / "datum-connect-network-helper").is_file():
        raise RuntimeError("--helper requires datum-connect-network-helper beside the daemon")
    if args.oidc and not args.helper:
        raise RuntimeError("--oidc requires --helper so the daemon runs as an ordinary user")
    if args.relay_only and (not args.discover or not args.relay_urls):
        raise RuntimeError("--relay-only requires --discover and --relay-urls")
    containers, networks = [], []
    sides = {role: tag + "-" + role for role in ("client", "peer")}
    ipv6 = args.ipv6 or args.ipv6_overlay
    family, host_prefix = ("-6", 128) if ipv6 else ("-4", 32)
    payload = 1232 if ipv6 else 1252
    addresses, keys = {}, {}

    def cmd(*words, stdin=None, check=True, timeout=60):
        result = subprocess.run([*docker, *map(str, words)], input=stdin, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"Docker {words[:3]}: {result.stdout[-1000:]}{result.stderr[-2000:]}")
        return result

    def execute(side, *words, **kwargs):
        return cmd("exec", "-i", sides[side], *words, **kwargs)

    def write_json(side, path, value):
        execute(side, "python3", "-c", "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.write(f,sys.stdin.buffer.read()); os.close(f)", path, stdin=json.dumps(value))

    def launch(side, label, command):
        execute(side, "python3", "-c",
                "import os,subprocess,sys,json; log=open('/lab/'+sys.argv[1]+'.log','ab'); "
                "identity={'user':1000,'group':1000,'extra_groups':[]} if sys.argv[2]=='yes' else {}; "
                "extra_env={'TEST_DATUM_HELPER_DIR':'/lab'} if sys.argv[3]=='yes' else {}; "
                "p=subprocess.Popen(json.loads(sys.stdin.read()),stdout=log,stderr=log,env={**os.environ,**extra_env,'RUST_LOG':'info,connect_transport=debug,datum_connect_daemon=debug'},**identity); "
                "open('/lab/'+sys.argv[1]+'.pid','w').write(str(p.pid))", label, "yes" if args.helper and label == "daemon" else "no", "yes" if args.oidc and label == "daemon" else "no", stdin=json.dumps(command))

    def stop(side, label, crash=False):
        execute(side, "python3", "-c", "import os,signal,sys,time; os.kill(int(open('/lab/'+sys.argv[1]+'.pid').read()),signal.SIGKILL if sys.argv[2]=='yes' else signal.SIGTERM); time.sleep(1)", label, "yes" if crash else "no")

    def wait_port(side, port):
        for _ in range(100):
            result = execute(side, "python3", "-c", "import socket,sys; socket.create_connection(('127.0.0.1',int(sys.argv[1])),.3).close()", port, check=False)
            if not result.returncode:
                return
            time.sleep(.1)
        raise AssertionError(f"{side} port {port} did not start; inspect logs")

    def cli(side, *words, expect=0):
        executable = ["/binaries/datumctl-connect"] if args.oidc else ["/binaries/datumctl", "connect"]
        context_env = {"DATUM_CREDENTIALS_HELPER":"/lab/datumctl-fixture", "DATUM_SESSION":"isolated-peer-session", "DATUM_API_HOST":"http://127.0.0.1:18080"} if args.oidc else {}
        result = execute(side, "python3", "-c",
            "import os,subprocess,sys; token=open('/lab/repo/daemon_auth/setup.token').read().strip(); "
            f"r=subprocess.run({executable!r}+sys.argv[1:],cwd='/lab',env={{**os.environ,**{context_env!r},'PATH':'/binaries:'+os.environ['PATH'],'DATUM_PROJECT':'demo','DATUMCTL_TRUSTED_PLUGINS':'connect','DATUM_CONNECT_TOKEN':token}}); sys.exit(r.returncode)",
            *words, "--output", "json", check=False)
        with (artifacts / "cli.log").open("a") as log:
            log.write(f"{side} {' '.join(words)}\n{result.stdout}{result.stderr}\n")
        assert (result.returncode == 0) == (expect == 0), f"{side} {words}: {result.stdout}{result.stderr}"
        return json.loads(result.stdout) if expect == 0 else result.stderr

    def absent(side):
        for _ in range(50):
            if execute(side, "ip", "link", "show", "dev", "dpip0", check=False).returncode:
                return
            time.sleep(.1)
        raise AssertionError(f"{side} retained a TUN after leave")

    def connected():
        last = {}
        for _ in range(120):
            last = {side: cli(side, "status") for side in sides}
            if all(state.get("networks") and state["networks"][0].get("connected") for state in last.values()):
                return last
            time.sleep(.25)
        raise AssertionError(f"Peers did not connect: {last}")

    def probe(side, remote):
        address = addresses[remote]
        execute(side, "ping", family, "-n", "-c", "5", "-W", "1", address)
        execute(side, "ping", family, "-n", "-c", "5", "-W", "1", "-M", "do", "-s", payload, address)
        host = f"[{address}]" if ipv6 else address
        actual = execute(side, "curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "5", f"http://{host}:8080/")
        assert actual.stdout.encode() == BODY
        execute(side, "python3", SCRIPT, "--udp-probe", address, "5353")

    def start(side, configured):
        command = ["/binaries/datum-connect-daemon", "--repo", "/lab/repo"]
        if args.relay_urls:
            command += ["--relay-urls", args.relay_urls]
        if configured:
            command += ["--local-ip-config", "/lab/ip.json"]
        if args.helper:
            execute(side, "chown", "1000:1000", "/lab")
            for path in ("/lab/credentials.json", "/lab/ip.json"):
                execute(side, "chown", "1000:1000", path, check=False)
        launch(side, "daemon", command)
        wait_port(side, 47780)
        if configured:
            # Health precedes asynchronous reconciliation and relay readiness.
            cli(side, "up")
        if args.helper:
            execute(side, "python3", "-c", "p=open('/lab/daemon.pid').read().strip(); s=open('/proc/'+p+'/status').read(); assert 'Uid:\\t1000\\t1000\\t1000\\t1000' in s; assert 'CapEff:\\t0000000000000000' in s")

    try:
        network = tag + "-underlay"
        options = []
        if ipv6:
            prefix = f"fd{tag[-10:-8]}:{tag[-8:-4]}:{tag[-4:]}"
            if args.ipv6:
                options = ["--ipv6", "--ipv4=false", "--subnet", f"{prefix}:1::/64"]
            addresses = {"client": f"{prefix}:2::2", "peer": f"{prefix}:2::3"}
            spoof_address, denied_address = f"{prefix}:2::98", f"{prefix}:2::99"
        else:
            addresses = {"client": "192.0.2.2", "peer": "192.0.2.3"}
            spoof_address, denied_address = "192.0.2.98", "192.0.2.99"
        cmd("network", "create", *([] if args.relay_urls else ["--internal"]), "--label", f"datum.connect.ip-lab={tag}", *options, network)
        networks.append(network)
        physical = {}
        for side, name in sides.items():
            cmd("run", "-d", "--name", name, "--label", f"datum.connect.ip-lab={tag}", "--network", network,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun",
                *(["--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "KILL"] if args.helper else []),
                "--security-opt", "no-new-privileges", "--tmpfs", "/lab:mode=700",
                "--mount", f"type=bind,src={WORKSPACE},dst=/workspace,readonly",
                "--mount", f"type=bind,src={binaries},dst=/binaries,readonly", args.image, "sleep", "infinity")
            containers.append(name)
            info = json.loads(cmd("inspect", name).stdout)[0]["NetworkSettings"]["Networks"][network]
            physical[side] = info["GlobalIPv6Address" if args.ipv6 else "IPAddress"]
            if args.ipv6:
                interfaces = json.loads(execute(side, "ip", "-j", "-4", "address").stdout)
                assert all(not item.get("addr_info") for item in interfaces if item["ifname"] != "lo")
            launch(side, "platform", ["python3", SCRIPT, "--fixture"])
            wait_port(side, 18080)
            write_json(side, "/lab/credentials.json", {"type": "connector", "project_id": "demo", "api_endpoint": "http://127.0.0.1:18080", "token_uri": "http://127.0.0.1:18080/token", "client_id": "local-peer-ip-lab", "refresh_token": "test-refresh-secret"})
            if args.oidc:
                execute(side, "cp", "/workspace/connect/scripts/fixtures/datumctl-oidc-helper.py", "/lab/datumctl-fixture")
                execute(side, "chmod", "700", "/lab/datumctl-fixture")
                write_json(side, "/lab/helper-state.json", {"session":"isolated-peer-session", "generation":1, "token":"test-access-secret", "expiry_seconds":5})
                execute(side, "chown", "1000:1000", "/lab/datumctl-fixture", "/lab/helper-state.json")
            start(side, False)
            enrolled = cli(side, "up", *( ["--auth", "oidc"] if args.oidc else ["--credentials-file", "/lab/credentials.json"] ))
            keys[side] = enrolled["connector"]["public_key"]
            if args.oidc:
                assert enrolled["authentication"]["kind"] == "oidc"
            stop(side, "daemon")
        configs = {}
        for side, remote in (("client", "peer"), ("peer", "client")):
            hint = f"[{physical[remote]}]:7777" if args.ipv6 else f"{physical[remote]}:7777"
            binding = {"project": "demo", "network": "peer-net", "peer": keys[remote], "addresses": [hint],
                "assigned_address": f"{addresses[side]}/{host_prefix}", "peer_address": f"{addresses[remote]}/{host_prefix}",
                "interface_name": "dpip0", "mtu": 1280,
                "allow_inbound": [{"protocol": "tcp", "ports": [8080, 8082]}, {"protocol": "udp", "ports": [5353, 5355]}, {"protocol": "icmp_echo"}],
                "allow_outbound": [{"protocol": "tcp", "ports": [8080, 8081]}, {"protocol": "udp", "ports": [5353, 5354]}, {"protocol": "icmp_echo"}]}
            configs[side] = {"underlay_address": physical[side], "underlay_port": 7777, "peer_bindings": [binding]}
            if args.discover:
                binding["discover"] = True
                binding.pop("addresses")
            if args.helper:
                execute(side, "mkdir", "-m", "711", "/helper")
                approvals = {"allowed_uid": 1000, "approvals": [{key: binding[key] for key in ("interface_name", "assigned_address", "peer_address", "mtu")}]}
                write_json(side, "/helper/approvals.json", approvals)
                configs[side]["network_helper"] = "/helper/helper.sock"
                launch(side, "helper", ["/binaries/datum-connect-network-helper", "--config", "/helper/approvals.json", "--socket", "/helper/helper.sock"])
                for _ in range(100):
                    if execute(side, "test", "-S", "/helper/helper.sock", check=False).returncode == 0:
                        break
                    time.sleep(.1)
                assert execute(side, "test", "-S", "/helper/helper.sock", check=False).returncode == 0
            write_json(side, "/lab/ip.json", configs[side])
            start(side, True)
            assert cli(side, "status")["connector"]["public_key"] == keys[side]
            cli(side, "join", "unknown", expect=1)
            absent(side)
        if args.discover:
            published = {side: json.loads(execute(side, "curl", "--silent", "--fail", "http://127.0.0.1:18080/fixture/peers").stdout) for side in sides}
            for side, remote in (("client", "peer"), ("peer", "client")):
                if args.relay_only:
                    for value in published[remote]:
                        for address in endpoint_ip_addresses(value):
                            transport_family = "-6" if ":" in address else "-4"
                            prefix = 128 if ":" in address else 32
                            execute(side, "ip", transport_family, "route", "add", "blackhole", f"{address}/{prefix}")
                    # Keep Cloud discovery realistic; local blackhole routes,
                    # not omitted hints, prevent direct UDP/hole-punch traffic.
                execute(side, "curl", "--silent", "--fail", "-X", "POST", "--data-binary", "@-", "http://127.0.0.1:18080/fixture/peers", stdin=json.dumps(published[remote]))
        print("PASS persistent Connector keys, project enrollment, unknown-network denial", flush=True)
        if args.helper:
            print("PASS privileged helpers with UID 1000 daemons and zero effective capabilities", flush=True)
        if args.oidc:
            print("PASS user-session OIDC enrollment with privileged networking kept separate", flush=True)
        listener = max(keys, key=keys.get)
        initiator = next(side for side in sides if side != listener)
        first = cli(listener, "join", "peer-net")
        assert not first.get("connected"), "peer connected before the other device joined"
        cli(initiator, "join", "peer-net")
        connected()
        cli(listener, "join", "peer-net")
        for side in sides:
            launch(side, "origin", ["python3", SCRIPT, "--origin", addresses[side]])
        time.sleep(.3)
        probe("client", "peer")
        probe("peer", "client")
        print("PASS direct two-daemon ICMP, TCP, UDP and full 1280-byte packets in both directions; no gateway", flush=True)
        for side, remote in (("client", "peer"), ("peer", "client")):
            host = f"[{addresses[remote]}]" if ipv6 else addresses[remote]
            for port in (8081, 8082):
                assert execute(remote, "curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "2", f"http://{host}:{port}/").stdout.encode() == BODY
                result = execute(side, "curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "2", f"http://{host}:{port}/", check=False)
                assert result.returncode, f"unauthorized TCP {port} succeeded"
            for port in (5354, 5355):
                execute(remote, "python3", SCRIPT, "--udp-probe", addresses[remote], str(port))
                execute(side, "python3", SCRIPT, "--udp-probe", addresses[remote], str(port), "--denied")
        print("PASS independent inbound/outbound TCP and UDP policy; denied ports have live listeners", flush=True)
        before = execute("peer", "wc", "-l", "/lab/received.log").stdout.split()[0]
        execute("client", "python3", GATEWAY_SCRIPT, "--spoof", spoof_address, addresses["peer"])
        time.sleep(.3)
        assert before == execute("peer", "wc", "-l", "/lab/received.log").stdout.split()[0], "spoofed source reached peer"
        execute("peer", "ip", family, "address", "add", f"{denied_address}/{host_prefix}", "dev", "lo")
        launch("peer", "denied-origin", ["python3", SCRIPT, "--origin", denied_address])
        time.sleep(.3)
        execute("peer", "python3", SCRIPT, "--udp-probe", denied_address, "5353")
        before = execute("peer", "wc", "-l", "/lab/received.log").stdout.split()[0]
        execute("client", "ip", family, "route", "add", f"{denied_address}/{host_prefix}", "dev", "dpip0")
        execute("client", "python3", GATEWAY_SCRIPT, "--spoof", addresses["client"], denied_address)
        execute("client", "ip", family, "route", "delete", f"{denied_address}/{host_prefix}", "dev", "dpip0")
        time.sleep(.3)
        assert before == execute("peer", "wc", "-l", "/lab/received.log").stdout.split()[0]
        probe("client", "peer")
        print("PASS spoofed source and non-peer destination fail closed; no subnet/transit route", flush=True)
        cli("peer", "leave", "peer-net")
        absent("peer")
        # Either a disconnected/waiting attachment or a removed TUN is safe.
        for _ in range(40):
            status = cli("client", "status")["networks"][0]
            if not status.get("connected"):
                break
            time.sleep(.1)
        assert not status.get("connected"), "remote leave retained a connected session"
        absent("client")
        # An online relay lab has a default route after tunnel teardown. Testing
        # an arbitrary external route with ping would not test our authorization.
        assert "dpip0" not in execute("client", "ip", family, "route", "get", addresses["peer"], check=False).stdout
        cli("client", "join", "peer-net")
        cli("peer", "join", "peer-net")
        connected()
        probe("client", "peer")
        print("PASS remote leave revokes the session; explicit rejoin recovers", flush=True)
        stop("peer", "daemon")
        absent("peer")
        start("peer", True)
        assert not cli("peer", "status").get("networks"), "ephemeral joins persisted"
        assert cli("peer", "status")["connector"]["public_key"] == keys["peer"]
        cli("client", "join", "peer-net")
        cli("peer", "join", "peer-net")
        connected()
        probe("peer", "client")
        print("PASS daemon restart preserves identity and requires explicit rejoin", flush=True)
        if args.helper:
            stop("peer", "helper")
            absent("peer")
            assert not cli("peer", "status")["networks"][0].get("connected")
            launch("peer", "helper", ["/binaries/datum-connect-network-helper", "--config", "/helper/approvals.json", "--socket", "/helper/helper.sock"])
            time.sleep(.3)
            cli("client", "join", "peer-net")
            cli("peer", "join", "peer-net")
            connected()
            probe("client", "peer")
            print("PASS helper shutdown removes interface and routes; explicit rejoin recovers", flush=True)
            stop("peer", "helper", crash=True)
            absent("peer")
            launch("peer", "helper", ["/binaries/datum-connect-network-helper", "--config", "/helper/approvals.json", "--socket", "/helper/helper.sock"])
            time.sleep(.3)
            cli("client", "join", "peer-net")
            cli("peer", "join", "peer-net")
            connected()
            probe("client", "peer")
            print("PASS helper crash removes interface; lifetime lock permits safe stale-socket recovery", flush=True)
        stop("peer", "daemon")
        denied_config = json.loads(json.dumps(configs["peer"]))
        denied_config["peer_bindings"][0]["allow_inbound"] = []
        denied_config["peer_bindings"][0]["allow_outbound"] = []
        write_json("peer", "/lab/ip.json", denied_config)
        start("peer", True)
        cli("client", "join", "peer-net")
        cli("peer", "join", "peer-net")
        connected()
        for side, remote in (("client", "peer"), ("peer", "client")):
            host = f"[{addresses[remote]}]" if ipv6 else addresses[remote]
            assert execute(side, "ping", family, "-n", "-c", "1", "-W", "1", addresses[remote], check=False).returncode
            assert execute(side, "curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "2", f"http://{host}:8080/", check=False).returncode
            execute(side, "python3", SCRIPT, "--udp-probe", addresses[remote], "5353", "--denied")
        assert cli("peer", "status")["networks"][0]["acl_drops"] > 0
        print("PASS authenticated membership with empty ACLs grants no traffic; policy removal revokes previous access", flush=True)
        stop("peer", "daemon")
        write_json("peer", "/lab/ip.json", configs["peer"])
        start("peer", True)
        cli("client", "join", "peer-net")
        cli("peer", "join", "peer-net")
        connected()
        probe("client", "peer")
        execute("peer", "curl", "--fail", "--silent", "http://127.0.0.1:18080/fixture/revoke")
        for _ in range(45):
            if execute("peer", "ip", "link", "show", "dev", "dpip0", check=False).returncode:
                break
            time.sleep(1)
        absent("peer")
        absent("client")
        print("PASS Cloud authorization loss tears down peer attachment and routes", flush=True)
        execute("peer", "curl", "--fail", "--silent", "http://127.0.0.1:18080/fixture/restore")
        stop("peer", "daemon")
        start("peer", True)
        cli("client", "join", "peer-net")
        cli("peer", "join", "peer-net")
        states = connected()
        probe("client", "peer")
        probe("peer", "client")
        states = {side: cli(side, "status") for side in sides}
        (artifacts / "status.json").write_text(json.dumps(states, indent=2))
        snapshots = {}
        for side in sides:
            links = json.loads(execute(side, "ip", "-j", "address").stdout)
            routes = json.loads(execute(side, "ip", family, "-j", "route", "show", "table", "all").stdout)
            if args.ipv6:
                assert all(a["family"] != "inet" for item in links if item["ifname"] != "lo" for a in item.get("addr_info", []))
            snapshots[side] = {"addresses": links, "routes": routes}
            token = execute(side, "python3", "-c", "print(open('/lab/repo/daemon_auth/setup.token').read().strip())").stdout.strip()
            logs = execute(side, "python3", "-c", "print(open('/lab/daemon.log').read())").stdout
            for secret in (token, "test-access-secret", "test-refresh-secret"):
                assert secret not in logs
            assert "ip_connected" in logs, "missing IP transport diagnostics"
            if args.relay_only:
                connections = [json.loads(line) for line in logs.splitlines() if '"ip_connected"' in line]
                assert connections and all(event["fields"].get("path") == "relay" for event in connections), "direct path appeared in relay-only test"
        (artifacts / "network-state.json").write_text(json.dumps(snapshots, indent=2))
        (artifacts / "network-topology.json").write_text(cmd("network", "inspect", network).stdout)
        print("PASS peer status, path diagnostics, and credential-redacted logs", flush=True)
        print(f"PASS direct peer IPv{6 if ipv6 else 4} CONNECT-IP suite (simulated Cloud only)", flush=True)
        if args.keep:
            print(f"Retained lab: {artifacts / 'lab.json'}; peer address {addresses['peer']}", flush=True)
    finally:
        (artifacts / "lab.json").write_text(json.dumps({"tag": tag, "context": args.docker_context, "containers": containers,
            "networks": networks, "sides": sides, "addresses": addresses, "ip_version": 6 if ipv6 else 4}, indent=2))
        for name in containers:
            result = cmd("exec", name, "python3", "-c", "import pathlib,json; print(json.dumps({p.name:p.read_text(errors='replace') for p in pathlib.Path('/lab').glob('*.log')}))", check=False)
            if result.returncode == 0:
                directory = artifacts / name
                directory.mkdir(mode=0o700, exist_ok=True)
                for label, contents in json.loads(result.stdout).items():
                    if Path(label).name == label:
                        (directory / label).write_text(contents)
        if not args.keep:
            for name in reversed(containers):
                cmd("rm", "-f", name, check=False)
            for name in reversed(networks):
                cmd("network", "rm", name, check=False)


def shell(path, side):
    state = json.loads(path.read_text())
    name = state["sides"][side]
    docker = ["docker", "--context", state["context"]]
    resource = json.loads(subprocess.check_output([*docker, "inspect", name]))[0]
    if resource.get("Config", {}).get("Labels", {}).get("datum.connect.ip-lab") != state["tag"]:
        raise ValueError("Container ownership label differs")
    subprocess.run([*docker, "exec", "-it", "-w", "/lab", name, "python3", "-c",
        "import os; os.environ.update(PATH='/binaries:'+os.environ['PATH'],DATUM_PROJECT='demo',DATUMCTL_TRUSTED_PLUGINS='connect',HISTFILE='/dev/null',DATUM_CONNECT_TOKEN=open('/lab/repo/daemon_auth/setup.token').read().strip()); os.execvp('bash',['bash','--noprofile','--norc'])"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", default="colima-kata")
    parser.add_argument("--image", default="datum-connect-ip-lab:local")
    parser.add_argument("--binaries", type=Path, default=CONNECT / "target/peer-ip-linux-bin")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--ipv6-overlay", action="store_true", help="IPv6 peer addresses over an IPv4 underlay")
    parser.add_argument("--relay-urls", help="Explicit HTTPS relays; allows lab egress for relay enrollment (Cloud stays simulated)")
    parser.add_argument("--discover", action="store_true", help="Resolve pinned peers through simulated Connector resources including their real relay URLs")
    parser.add_argument("--relay-only", action="store_true", help="Blackhole direct peer addresses inside test containers; require relay paths in telemetry")
    parser.add_argument("--helper", action="store_true", help="Run daemons as UID 1000 without capabilities; root helpers own TUN interfaces")
    parser.add_argument("--oidc", action="store_true", help="Use isolated simulated datumctl OIDC sessions in user daemons (requires --helper)")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--datumctl-source", type=Path)
    parser.add_argument("--shell", type=Path)
    parser.add_argument("--side", choices=["client", "peer"], default="client")
    parser.add_argument("--cleanup", type=Path)
    parser.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--origin", help=argparse.SUPPRESS)
    parser.add_argument("--udp-probe", nargs=2, help=argparse.SUPPRESS)
    parser.add_argument("--denied", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture:
        fixture()
    elif args.origin:
        origin(args.origin)
    elif args.udp_probe:
        udp_probe(args.udp_probe[0], int(args.udp_probe[1]), args.denied)
    elif args.shell:
        shell(args.shell, args.side)
    else:
        helpers = module(WORKSPACE / "iroh-gateway/scripts/connect-ip-local.py", "ip_lab_helpers")
        if args.cleanup:
            helpers.cleanup(args.cleanup)
        else:
            if args.build:
                helpers.build(args)
                if args.helper:
                    subprocess.run(["docker", "--context", args.docker_context, "run", "--rm", "--cpus", "4", "--memory", "8g",
                        "--mount", f"type=bind,src={WORKSPACE},dst=/workspace,readonly",
                        "--mount", f"type=bind,src={args.binaries.resolve()},dst=/out",
                        "--mount", "type=volume,src=datum-connect-ip-cargo,target=/usr/local/cargo",
                        "--mount", "type=volume,src=datum-connect-ip-rustup,target=/usr/local/rustup",
                        "--mount", "type=volume,src=datum-connect-ip-target,target=/build",
                        "-e", "CARGO_TARGET_DIR=/build", "-e", "CARGO_BUILD_JOBS=4", "-e", "CARGO_PROFILE_DEV_DEBUG=0", "-e", "CARGO_INCREMENTAL=0",
                        "-w", "/workspace/connect/connect-lib", args.image, "sh", "-c",
                        "cargo build --locked -p datum-connect-network-helper && cp /build/debug/datum-connect-network-helper /out/"], check=True)
            run_lab(args)


if __name__ == "__main__":
    main()
