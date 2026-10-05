#!/usr/bin/env python3
"""Two real Connect daemons concurrently routed through one gateway into a VPC.

Cloud/OAuth are simulated. The daemons, iroh transport, gateway, Linux TUNs,
and IPv6 VPC packet path are real and isolated in disposable Docker resources.
"""
import argparse
import hashlib
import http.server
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


CONNECT = Path(__file__).resolve().parents[1]
GATEWAY = CONNECT.parent / "iroh-gateway"
BODY = b"real-connect-ip-tun-http\n"


def fixture():
    source = Path("/workspace/connect/scripts/daemon-e2e.py")
    spec = importlib.util.spec_from_file_location("cloud_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    http.server.ThreadingHTTPServer(("127.0.0.1", 18080), module.Platform).serve_forever()


def digest(*parts):
    value = hashlib.sha256()
    value.update(b"datum-connect/peer-host/v1\0")
    for part in parts:
        encoded = part.encode()
        value.update(len(encoded).to_bytes(8, "big"))
        value.update(encoded)
    return value.digest()


def attachment(project, network, client_key, gateway_key):
    first, second = sorted((client_key.lower(), gateway_key.lower()))

    def address(key):
        raw = bytearray(digest(project, network, first, second, key)[:16])
        raw[0] = 0xfd
        return str(ipaddress.IPv6Address(bytes(raw)))

    label = digest(project, network, first, second)[:7].hex()
    return address(client_key.lower()), address(gateway_key.lower()), "d" + label


def run(args):
    docker = ["docker", "--context", args.docker_context]
    tag = "connect-multi-" + uuid.uuid4().hex[:10]
    artifacts = Path(tempfile.mkdtemp(prefix=tag + "-", dir=CONNECT / "target"))
    binaries = args.binaries.resolve()
    for name in ("datum-connect-daemon", "iroh-gateway", "datumctl-connect"):
        if not (binaries / name).is_file():
            raise RuntimeError(f"missing {binaries / name}")
    containers, networks = [], []

    def cmd(*words, stdin=None, check=True, timeout=90):
        result = subprocess.run([*docker, *map(str, words)], input=stdin, text=True,
                                capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"docker {words[:3]} failed: {result.stdout[-1000:]}{result.stderr[-3000:]}")
        return result

    def execute(name, *words, **kwargs):
        return cmd("exec", "-i", name, *words, **kwargs)

    def write_json(name, path, value):
        execute(name, "python3", "-c",
                "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.write(f,sys.stdin.buffer.read()); os.close(f)",
                path, stdin=json.dumps(value))

    def launch(name, label, command):
        execute(name, "python3", "-c",
                "import json,os,subprocess,sys; log=open('/lab/'+sys.argv[1]+'.log','ab'); "
                "p=subprocess.Popen(json.loads(sys.stdin.read()),stdout=log,stderr=log,env={**os.environ,'RUST_LOG':'info,connect_transport=debug,iroh_gateway=debug,datum_connect_daemon=debug'}); "
                "open('/lab/'+sys.argv[1]+'.pid','w').write(str(p.pid))",
                label, stdin=json.dumps(command))

    def stop(name, label):
        execute(name, "python3", "-c",
                "import os,signal,sys,time; os.kill(int(open('/lab/'+sys.argv[1]+'.pid').read()),signal.SIGTERM); time.sleep(1)", label)

    def wait_port(name, port, host="127.0.0.1"):
        for _ in range(120):
            result = execute(name, "python3", "-c",
                             "import socket,sys; socket.create_connection((sys.argv[1],int(sys.argv[2])),.3).close()",
                             host, port, check=False)
            if not result.returncode:
                return
            time.sleep(.1)
        raise AssertionError(f"{name}:{port} did not start")

    def cli(name, *words, expect=0):
        result = execute(name, "python3", "-c",
                         "import os,subprocess,sys; token=open('/lab/repo/daemon_auth/setup.token').read().strip(); "
                         "r=subprocess.run(['/binaries/datumctl-connect',*sys.argv[1:]],cwd='/lab',env={**os.environ,'PATH':'/binaries:'+os.environ['PATH'],'DATUM_PROJECT':'demo','DATUM_CONNECT_TOKEN':token}); sys.exit(r.returncode)",
                         *words, "--output", "json", check=False)
        with (artifacts / "cli.log").open("a") as output:
            output.write(f"{name} {' '.join(words)}\n{result.stdout}{result.stderr}\n")
        assert (result.returncode == 0) == (expect == 0), result.stdout + result.stderr
        return json.loads(result.stdout) if expect == 0 else result.stderr

    def container(role, network, address=None, tun=False):
        name = f"{tag}-{role}"
        options = ["run", "-d", "--name", name, "--label", f"datum.connect.multi-device={tag}",
                   "--network", network, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/lab:mode=700",
                   "--mount", f"type=bind,src={CONNECT},dst=/workspace/connect,readonly",
                   "--mount", f"type=bind,src={GATEWAY},dst=/workspace/iroh-gateway,readonly",
                   "--mount", f"type=bind,src={binaries},dst=/binaries,readonly"]
        if address:
            options += ["--ip6", address]
        if tun:
            options += ["--device", "/dev/net/tun"]
        if role == "gateway":
            options += ["--sysctl", "net.ipv6.conf.all.forwarding=1"]
        cmd(*options, args.image, "sleep", "infinity")
        containers.append(name)
        return name

    try:
        (CONNECT / "target").mkdir(exist_ok=True)
        prefix = f"fd{tag[-10:-8]}:{tag[-8:-4]}:{tag[-4:]}"
        vpc_subnet = f"{prefix}:2::/64"
        underlay, vpc = tag + "-underlay", tag + "-vpc"
        # Enrollment requires a live relay connection before publishing each
        # device identity. The overlay VPC below remains fully internal.
        cmd("network", "create", "--label", f"datum.connect.multi-device={tag}", underlay)
        networks.append(underlay)
        cmd("network", "create", "--internal", "--ipv6", "--ipv4=false", "--subnet", vpc_subnet,
            "--label", f"datum.connect.multi-device={tag}", vpc)
        networks.append(vpc)
        clients = {role: container(role, underlay, tun=True) for role in ("device-a", "device-b")}
        gateway = container("gateway", underlay, tun=True)
        origin_ip, gateway_vpc = f"{prefix}:2::3", f"{prefix}:2::2"
        origin = container("origin", vpc, origin_ip)
        cmd("network", "connect", "--ip6", gateway_vpc, vpc, gateway)
        inspect = json.loads(cmd("inspect", gateway).stdout)[0]
        gateway_ip = inspect["NetworkSettings"]["Networks"][underlay]["IPAddress"]
        gateway_socket = f"{gateway_ip}:7777"
        gateway_key = execute(gateway, "/binaries/iroh-gateway", "--key-file", "/lab/gateway.key", "--print-endpoint-id").stdout.strip()

        client_keys = {}
        for role, name in clients.items():
            launch(name, "platform", ["python3", "/workspace/connect/scripts/connect-vpc-multi-device-local.py", "--fixture"])
            wait_port(name, 18080)
            write_json(name, "/lab/credentials.json", {"type": "connector", "project_id": "demo",
                       "api_endpoint": "http://127.0.0.1:18080", "token_uri": "http://127.0.0.1:18080/token",
                       "client_id": "multi-device-lab", "refresh_token": "test-refresh-secret"})
            launch(name, "daemon", ["/binaries/datum-connect-daemon", "--repo", "/lab/repo"])
            wait_port(name, 47780)
            client_keys[role] = cli(name, "up", "--credentials-file", "/lab/credentials.json")["connector"]["public_key"]
            stop(name, "daemon")

        attachments = {}
        for role in clients:
            assigned, gateway_tun, interface = attachment("demo", "local-vpc", client_keys[role], gateway_key)
            attachments[role] = {"assigned": assigned, "gateway": gateway_tun, "interface": interface}

        grants = []
        for role, name in clients.items():
            values = attachments[role]
            peer_routes = [other["assigned"] + "/128" for other_role, other in attachments.items()
                           if other_role != role]
            client_ip = json.loads(cmd("inspect", name).stdout)[0]["NetworkSettings"]["Networks"][underlay]["IPAddress"]
            binding = {"project": "demo", "network": "local-vpc", "gateway": gateway_key,
                       "addresses": [gateway_socket], "assigned_address": values["assigned"] + "/128",
                       "routes": [vpc_subnet, *peer_routes], "interface_name": "dcvpc0", "mtu": 1280}
            write_json(name, "/lab/ip.json", {"underlay_address": client_ip, "bindings": [binding]})
            launch(name, "daemon", ["/binaries/datum-connect-daemon", "--repo", "/lab/repo", "--local-ip-config", "/lab/ip.json"])
            wait_port(name, 47780)
            grants.append({"network": "local-vpc", "peer": client_keys[role],
                           "client_address": values["assigned"] + "/128",
                           "gateway_address": values["gateway"] + "/128",
                           "routes": [vpc_subnet], "peer_routes": peer_routes,
                           "interface_name": values["interface"], "mtu": 1280})

        assert len({item["interface_name"] for item in grants}) == 2, grants
        assert len({item["client_address"] for item in grants}) == 2, grants
        assert len({item["gateway_address"] for item in grants}) == 2, grants
        write_json(gateway, "/lab/ip.json", {"grants": grants})
        write_json(gateway, "/lab/gateway.json", {"ipv4_addr": gateway_socket,
                   "discovery_mode": "static", "transport": "masque"})
        launch(gateway, "gateway", ["/binaries/iroh-gateway", "--key-file", "/lab/gateway.key",
               "--config-file", "/lab/gateway.json", "--ip-config", "/lab/ip.json",
               "--metrics-addr", "127.0.0.1", "--metrics-port", "9090"])
        wait_port(gateway, 8080)
        for values in attachments.values():
            execute(origin, "ip", "-6", "route", "add", values["assigned"] + "/128", "via", gateway_vpc)
        launch(origin, "origin", ["python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--origin", "--ipv6"])
        wait_port(origin, 8080, "::1")

        for name in clients.values():
            cli(name, "join", "local-vpc")
        for role, name in clients.items():
            execute(name, "ping", "-6", "-n", "-c", "3", "-W", "2", origin_ip)
            response = execute(name, "curl", "--noproxy", "*", "--fail", "--max-time", "5", f"http://[{origin_ip}]:8080/")
            assert response.stdout.encode() == BODY
            execute(name, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--udp-probe", origin_ip)
            assert execute(name, "ip", "link", "show", "dev", "dcvpc0", check=False).returncode == 0
            status = cli(name, "status")["networks"][0]
            assert status["running"] and status["packets_sent"] > 0 and status["packets_received"] > 0, status

        def gateway_counters():
            metrics = execute(gateway, "curl", "--fail", "--silent", "http://127.0.0.1:9090/metrics").stdout
            return metrics, dict(line.split() for line in metrics.splitlines()
                                 if line.startswith("iroh_gateway_ip_"))

        _, before_peer = gateway_counters()
        for role, name in clients.items():
            launch(name, "peer-origin", ["python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--origin", "--ipv6"])
            wait_port(name, 8080, attachments[role]["assigned"])
        for role, name in clients.items():
            other_role = next(candidate for candidate in clients if candidate != role)
            other_name = clients[other_role]
            destination = attachments[other_role]["assigned"]
            execute(name, "ping", "-6", "-n", "-c", "3", "-W", "2", destination)
            response = execute(name, "curl", "--noproxy", "*", "--fail", "--max-time", "5", f"http://[{destination}]:8080/")
            assert response.stdout.encode() == BODY
            execute(name, "python3", "/workspace/iroh-gateway/scripts/connect-ip-local.py", "--udp-probe", destination)
            expected_source = attachments[role]["assigned"]
            received = execute(other_name, "python3", "-c",
                               "import json,sys; rows=[json.loads(line) for line in open('/lab/origin-received.log')]; "
                               "assert any(row['source']==sys.argv[1] for row in rows), rows",
                               expected_source, check=False)
            assert received.returncode == 0, received.stdout + received.stderr

        for values in attachments.values():
            assert execute(gateway, "ip", "link", "show", "dev", values["interface"], check=False).returncode == 0
        metrics, counters = gateway_counters()
        assert int(counters["iroh_gateway_ip_active_sessions"]) == 2, counters
        assert int(counters["iroh_gateway_ip_packets_injected_total"]) > 0
        assert int(counters["iroh_gateway_ip_packets_returned_total"]) > 0
        for counter in ("iroh_gateway_ip_packets_injected_total", "iroh_gateway_ip_packets_returned_total"):
            assert counters[counter] == before_peer[counter], (counter, before_peer[counter], counters[counter])
        (artifacts / "grants.json").write_text(json.dumps({"grants": grants}, indent=2))
        (artifacts / "metrics.txt").write_text(metrics)
        print(f"PASS two simultaneous device daemons use distinct gateway TUNs and addresses: {attachments}")
        print("PASS both devices routed ICMP, TCP, and UDP through one real gateway into the IPv6 VPC")
        print("PASS devices routed ICMP, TCP, and UDP directly through the gateway with their assigned source addresses")
        print(f"Artifacts: {artifacts}")
    finally:
        for name in containers:
            result = execute(name, "python3", "-c", "import pathlib,json; print(json.dumps({p.name:p.read_text(errors='replace') for p in pathlib.Path('/lab').glob('*.log')}))", check=False)
            if result.returncode == 0:
                directory = artifacts / name
                directory.mkdir(exist_ok=True)
                for label, contents in json.loads(result.stdout).items():
                    (directory / label).write_text(contents)
        if not args.keep:
            for name in reversed(containers):
                cmd("rm", "-f", name, check=False)
            for name in reversed(networks):
                cmd("network", "rm", name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", default="colima")
    parser.add_argument("--image", default="datum-connect-multi-device-lab:local")
    parser.add_argument("--binaries", type=Path, default=CONNECT / "target/connect-ip-linux-bin")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture:
        fixture()
    else:
        run(args)


if __name__ == "__main__":
    main()
