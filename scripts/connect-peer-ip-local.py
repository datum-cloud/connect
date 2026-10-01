#!/usr/bin/env python3
"""Two-daemon CONNECT-IP lab, with no gateway in the data path.

Only Cloud/OAuth are simulated. All Docker networks/containers are disposable,
uniquely labeled, and isolated from the host. --ipv6 disables non-loopback IPv4.
"""
import argparse
import http.server
import importlib.util
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


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture():
    base = module(CONNECT / "scripts/daemon-e2e.py", "cloud_fixture")

    class Platform(base.Platform):
        def handle_api(self):
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
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1 if denied else 5)
        for data in ([b"denied"] if denied else [b"peer-ip", b"", bytes(range(256)) * 4, bytes(maximum)]):
            sock.sendto(data, (address, port))
            try:
                received, _ = sock.recvfrom(65535)
            except socket.timeout:
                if denied:
                    return
                raise
            assert not denied, "unapproved UDP port replied"
            assert received == data, "UDP data changed"


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
    containers, networks = [], []
    sides = {role: tag + "-" + role for role in ("client", "peer")}
    ipv6 = args.ipv6
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
                "p=subprocess.Popen(json.loads(sys.stdin.read()),stdout=log,stderr=log,env={**os.environ,'RUST_LOG':'info,connect_transport=debug,datum_connect_daemon=debug'}); "
                "open('/lab/'+sys.argv[1]+'.pid','w').write(str(p.pid))", label, stdin=json.dumps(command))

    def stop(side, label):
        execute(side, "python3", "-c", "import os,signal,sys,time; os.kill(int(open('/lab/'+sys.argv[1]+'.pid').read()),signal.SIGTERM); time.sleep(1)", label)

    def wait_port(side, port):
        for _ in range(100):
            result = execute(side, "python3", "-c", "import socket,sys; socket.create_connection(('127.0.0.1',int(sys.argv[1])),.3).close()", port, check=False)
            if not result.returncode:
                return
            time.sleep(.1)
        raise AssertionError(f"{side} port {port} did not start; inspect logs")

    def cli(side, *words, expect=0):
        result = execute(side, "python3", "-c",
            "import os,subprocess,sys; token=open('/lab/repo/daemon_auth/setup.token').read().strip(); "
            "r=subprocess.run(['/binaries/datumctl','connect',*sys.argv[1:]],cwd='/lab',env={**os.environ,'PATH':'/binaries:'+os.environ['PATH'],'DATUM_PROJECT':'demo','DATUMCTL_TRUSTED_PLUGINS':'connect','DATUM_CONNECT_TOKEN':token}); sys.exit(r.returncode)",
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
        execute(side, "ping", family, "-n", "-c", "1", "-W", "3", address)
        execute(side, "ping", family, "-n", "-c", "1", "-W", "3", "-M", "do", "-s", payload, address)
        host = f"[{address}]" if ipv6 else address
        actual = execute(side, "curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "5", f"http://{host}:8080/")
        assert actual.stdout.encode() == BODY
        execute(side, "python3", SCRIPT, "--udp-probe", address, "5353")

    def start(side, configured):
        command = ["/binaries/datum-connect-daemon", "--repo", "/lab/repo"]
        if configured:
            command += ["--local-ip-config", "/lab/ip.json"]
        launch(side, "daemon", command)
        wait_port(side, 47780)

    try:
        network = tag + "-underlay"
        options = []
        if ipv6:
            prefix = f"fd{tag[-10:-8]}:{tag[-8:-4]}:{tag[-4:]}"
            options = ["--ipv6", "--ipv4=false", "--subnet", f"{prefix}:1::/64"]
            addresses = {"client": f"{prefix}:2::2", "peer": f"{prefix}:2::3"}
            spoof_address, denied_address = f"{prefix}:2::98", f"{prefix}:2::99"
        else:
            addresses = {"client": "192.0.2.2", "peer": "192.0.2.3"}
            spoof_address, denied_address = "192.0.2.98", "192.0.2.99"
        cmd("network", "create", "--internal", "--label", f"datum.connect.ip-lab={tag}", *options, network)
        networks.append(network)
        physical = {}
        for side, name in sides.items():
            cmd("run", "-d", "--name", name, "--label", f"datum.connect.ip-lab={tag}", "--network", network,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun",
                "--security-opt", "no-new-privileges", "--tmpfs", "/lab:mode=700",
                "--mount", f"type=bind,src={WORKSPACE},dst=/workspace,readonly",
                "--mount", f"type=bind,src={binaries},dst=/binaries,readonly", args.image, "sleep", "infinity")
            containers.append(name)
            info = json.loads(cmd("inspect", name).stdout)[0]["NetworkSettings"]["Networks"][network]
            physical[side] = info["GlobalIPv6Address" if ipv6 else "IPAddress"]
            if ipv6:
                interfaces = json.loads(execute(side, "ip", "-j", "-4", "address").stdout)
                assert all(not item.get("addr_info") for item in interfaces if item["ifname"] != "lo")
            launch(side, "platform", ["python3", SCRIPT, "--fixture"])
            wait_port(side, 18080)
            write_json(side, "/lab/credentials.json", {"type": "connector", "project_id": "demo", "api_endpoint": "http://127.0.0.1:18080", "token_uri": "http://127.0.0.1:18080/token", "client_id": "local-peer-ip-lab", "refresh_token": "test-refresh-secret"})
            start(side, False)
            keys[side] = cli(side, "up", "--credentials-file", "/lab/credentials.json")["connector"]["public_key"]
            stop(side, "daemon")
        configs = {}
        for side, remote in (("client", "peer"), ("peer", "client")):
            hint = f"[{physical[remote]}]:7777" if ipv6 else f"{physical[remote]}:7777"
            binding = {"project": "demo", "network": "peer-net", "peer": keys[remote], "addresses": [hint],
                "assigned_address": f"{addresses[side]}/{host_prefix}", "peer_address": f"{addresses[remote]}/{host_prefix}",
                "interface_name": "dpip0", "mtu": 1280,
                "allow_inbound": [{"protocol": "tcp", "ports": [8080, 8082]}, {"protocol": "udp", "ports": [5353, 5355]}, {"protocol": "icmp_echo"}],
                "allow_outbound": [{"protocol": "tcp", "ports": [8080, 8081]}, {"protocol": "udp", "ports": [5353, 5354]}, {"protocol": "icmp_echo"}]}
            configs[side] = {"underlay_address": physical[side], "underlay_port": 7777, "peer_bindings": [binding]}
            write_json(side, "/lab/ip.json", configs[side])
            start(side, True)
            assert cli(side, "status")["connector"]["public_key"] == keys[side]
            cli(side, "join", "unknown", expect=1)
            absent(side)
        print("PASS persistent Connector keys, project enrollment, unknown-network denial", flush=True)
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
        assert execute("client", "ping", family, "-n", "-c", "1", "-W", "2", addresses["peer"], check=False).returncode
        # Either a disconnected/waiting attachment or a removed TUN is safe.
        for _ in range(40):
            status = cli("client", "status")["networks"][0]
            if not status.get("connected"):
                break
            time.sleep(.1)
        assert not status.get("connected"), "remote leave retained a connected session"
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
        assert execute("client", "ping", family, "-n", "-c", "1", "-W", "2", addresses["peer"], check=False).returncode
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
            if ipv6:
                assert all(a["family"] != "inet" for item in links if item["ifname"] != "lo" for a in item.get("addr_info", []))
            snapshots[side] = {"addresses": links, "routes": routes}
            token = execute(side, "python3", "-c", "print(open('/lab/repo/daemon_auth/setup.token').read().strip())").stdout.strip()
            logs = execute(side, "python3", "-c", "print(open('/lab/daemon.log').read())").stdout
            for secret in (token, "test-access-secret", "test-refresh-secret"):
                assert secret not in logs
            assert "ip_connected" in logs, "missing IP transport diagnostics"
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
            run_lab(args)


if __name__ == "__main__":
    main()
