#!/usr/bin/env python3
"""Validate Connect subnet routing on the dedicated staging lab instances.

Deploy staging-subnet-lab.yaml separately with your authorized datumctl session.
This script changes only these three named lab instances. It does not alter the
host's Connect daemon, firewall, credentials, or installed plugin. Credentials
are provided explicitly and never logged. Lab resources remain for inspection.
"""
import argparse
import io
import json
from pathlib import Path
import socket
import subprocess
import tarfile
import time

PROJECT = "datum-cloud"
NETWORK = "staging-vpc"
PREFIX = "fd20:0:27::/48"
INSTANCES = {role: f"connect-subnet-lab-{role}-dfw-us-central-1-0" for role in ("router", "client", "origin")}
TOKEN = "/lab/daemon/daemon_auth/setup.token"
HELPER = "/var/lib/datum-connect-network-1000"
ROOT = Path(__file__).resolve().parents[1]
MANAGEMENT = None


def remote(role, *command, data=None, check=True, timeout=180):
    prefix = (["kubectl", "--context", MANAGEMENT[0], "-n", MANAGEMENT[1], "exec", INSTANCES[role], "-c", "lab"]
              if MANAGEMENT else ["datumctl", "compute", "exec", INSTANCES[role], "--project", PROJECT])
    result = subprocess.run([*prefix, *( ["-i"] if data is not None else []), "--", *command],
                            input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{role}: {command[:2]} failed: {result.stdout[-1500:].decode(errors='replace')} {result.stderr[-1500:].decode(errors='replace')}")
    return result


def python(role, code, *args, **kwargs):
    return remote(role, "python3", "-c", code, *args, **kwargs)


def cli(role, *args, check=True):
    result = remote(role, "env", "PATH=/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "DATUMCTL_TRUSTED_PLUGINS=connect", "/lab/bin/datumctl", "connect", *args,
                    "--project", PROJECT, "--token-file", TOKEN, "--output", "json", "--timeout", "90s", check=check)
    if check:
        return json.loads(result.stdout)
    return result


def api(role, path):
    code = "import json,urllib.request; token=open('/lab/daemon/daemon_auth/setup.token').read().strip(); r=urllib.request.Request('http://127.0.0.1:47780'+__import__('sys').argv[1]+'?project=datum-cloud',headers={'Authorization':'Bearer '+token}); print(urllib.request.urlopen(r).read().decode())"
    return json.loads(python(role, code, path).stdout)


def upload(role, files):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        for source, target, mode in files:
            data = Path(source).read_bytes()
            info = tarfile.TarInfo(target)
            info.size, info.mode = len(data), mode
            stream.addfile(info, io.BytesIO(data))
    remote(role, "sh", "-ec", "mkdir -p /lab && tar -xzf - -C /lab", data=archive.getvalue())


def launch(role, name, command, user=False):
    code = """import json,os,subprocess,sys
name=sys.argv[1]
pidfile='/lab/'+name+'.pid'
if os.path.exists(pidfile):
 try: os.kill(int(open(pidfile).read()),0)
 except ProcessLookupError: pass
 else: raise RuntimeError('refusing to start duplicate '+name)
log=open('/lab/'+name+'.log','ab')
identity={'user':1000,'group':1000,'extra_groups':[]} if sys.argv[2]=='user' else {}
p=subprocess.Popen(json.loads(sys.stdin.read()),stdout=log,stderr=log,start_new_session=True,
 env={**os.environ,'HOME':'/home/ubuntu','RUST_LOG':'info,datum_connect_daemon=debug,connect_transport=debug'},**identity)
open(pidfile,'w').write(str(p.pid))
print(name,p.pid)
"""
    python(role, code, name, "user" if user else "root", data=json.dumps(command).encode())


def deploy(args):
    for role in args.roles:
        upload(role, [(args.binaries/name, "bin/"+name, 0o755) for name in
                      ("datumctl", "datumctl-connect", "datum-connectd", "datum-connect-network-helper")]
                    + [(args.credentials, "credentials.json", 0o600)])
        remote(role, "sh", "-ec", "id ubuntu; install -d -m 700 -o 1000 -g 1000 /lab/daemon; chown 1000:1000 /lab/credentials.json")
        launch(role, "daemon", ["/lab/bin/datum-connectd", "--repo", "/lab/daemon"], user=True)
        print(role, cli(role, "up", "--credentials-file", "/lab/credentials.json", "--name", f"connect-subnet-lab-{role}"), flush=True)
    if not args.skip_origin:
        upload("origin", [(Path(__file__), "staging-subnet-lab.py", 0o755)])
        launch("origin", "origin", ["python3", "/lab/staging-subnet-lab.py", "origin"])


def enroll(args):
    """Retry enrollment after a relay outage without replacing running binaries."""
    for role in args.roles:
        print(role, cli(role, "up", "--auth", "stored"), flush=True)


def upgrade(args):
    """Replace only this lab's daemon binary, preserving identity and saved state."""
    stop = """import os,subprocess,time
p=int(open('/lab/daemon.pid').read())
check_and_stop="import os,signal,sys; p=int(sys.argv[1]); assert os.readlink('/proc/'+str(p)+'/exe')=='/lab/bin/datum-connectd'; os.kill(p,signal.SIGTERM)"
subprocess.run(['python3','-c',check_and_stop,str(p)],user=1000,group=1000,extra_groups=[],check=True)
for _ in range(100):
 try: state=open('/proc/'+str(p)+'/stat').read().split()[2]
 except FileNotFoundError: break
 if state=='Z': break
 time.sleep(.1)
else: raise RuntimeError('daemon did not stop; refusing binary replacement')
os.unlink('/lab/daemon.pid')
"""
    for role in args.roles:
        python(role, stop)
        upload(role, [(args.binaries/"datum-connectd", "bin/datum-connectd", 0o755)])
        launch(role, "daemon", ["/lab/bin/datum-connectd", "--repo", "/lab/daemon"], user=True)
        print(role, "daemon replaced; run enroll, then explicitly rejoin attachments", flush=True)


def addresses():
    values = {}
    for role in INSTANCES:
        rows = json.loads(remote(role, "ip", "-j", "-6", "address", "show", "dev", "eth0").stdout)
        values[role] = next(a["local"] for a in rows[0]["addr_info"] if a["scope"] == "global")
    return values


def probe_http(role, address, port=8080, allowed=True):
    result = remote(role, "curl", "-6", "--noproxy", "*", "--connect-timeout", "3", "--max-time", "8", "-fsS",
                    f"http://[{address}]:{port}/", check=False)
    if allowed:
        assert result.returncode == 0 and result.stdout == b"staging-connect-subnet\n", result.stderr.decode()
    else:
        assert result.returncode != 0, "unapproved HTTP traffic succeeded"


def enable_router_forwarding():
    # procps can exit zero and print '= 1' even when /proc/sys is read-only.
    # Read the kernel value back before creating attachments or claiming success.
    result = remote("router", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1", check=False)
    actual = remote("router", "sysctl", "-n", "net.ipv6.conf.all.forwarding").stdout.strip()
    if result.returncode or actual != b"1":
        raise RuntimeError(
            "Router IPv6 forwarding is disabled. This runtime must permit the operator "
            "to enable net.ipv6.conf.all.forwarding before subnet routing can work. "
            "No new attachments were created. " + result.stderr.decode(errors="replace").strip())


def attach(args):
    addrs = addresses()
    print("Physical addresses:", addrs, flush=True)
    probe_http("router", addrs["origin"])
    probe_http("client", addrs["origin"], allowed=False)
    print("PASS: router reaches origin; isolated client cannot reach origin before Connect", flush=True)
    plans = {}
    for role, other, flag in (("router", "client", "--advertise-routes"), ("client", "router", "--routes")):
        result = cli(role, "join", NETWORK, "--peer", f"connect-subnet-lab-{other}", flag, PREFIX,
                     "--allow-tcp", "8080", "--allow-udp", "5353", "--allow-ping", check=False)
        assert result.returncode and b"administrator approval" in result.stderr, result.stderr.decode()
        plan = api(role, f"/v1/networks/{NETWORK}/setup")
        plans[role] = plan
        python(role, "import os,sys; os.makedirs(sys.argv[1],mode=0o711,exist_ok=True); p=sys.argv[1]+'/config.json'; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,sys.stdin.buffer.read()); os.close(f)",
               HELPER, data=json.dumps(plan["helper_config"]).encode())
        launch(role, "helper", ["/lab/bin/datum-connect-network-helper", "--config", HELPER+"/config.json", "--socket", HELPER+"/helper.sock"])
    router = plans["router"]["binding"]
    # Exact lab-owned table. Never flush another operator's rules.
    nft = f"""table ip6 datum_connect_lab {{
 chain forward {{ type filter hook forward priority filter; policy drop;
  iifname "{router['interface_name']}" oifname "eth0" ip6 saddr {router['peer_address']} ip6 daddr {PREFIX} tcp dport 8080 accept
  iifname "{router['interface_name']}" oifname "eth0" ip6 saddr {router['peer_address']} ip6 daddr {PREFIX} udp dport 5353 accept
  iifname "{router['interface_name']}" oifname "eth0" ip6 saddr {router['peer_address']} ip6 daddr {PREFIX} icmpv6 type echo-request accept
  iifname "eth0" oifname "{router['interface_name']}" ip6 daddr {router['peer_address']} ct state established,related accept
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
  oifname "eth0" ip6 saddr {router['peer_address']} ip6 daddr {PREFIX} masquerade
 }}
}}
"""
    remote("router", "nft", "-f", "-", data=nft.encode())
    enable_router_forwarding()
    for role in ("router", "client"):
        print(role, cli(role, "join", NETWORK), flush=True)
    args.artifacts.mkdir(parents=True, exist_ok=True)
    (args.artifacts/"plans.json").write_text(json.dumps(plans, indent=2))
    wait_connected()


def attachment(status):
    return next(n for n in status["networks"] if n["network"] == NETWORK)


def wait_connected():
    for _ in range(20):
        statuses = {role: cli(role, "status") for role in ("router", "client")}
        if all(attachment(value).get("connected") for value in statuses.values()):
            return statuses
        time.sleep(2)
    raise RuntimeError("Peers did not connect: "+json.dumps(statuses))


def test(args):
    addrs = addresses()
    forwarding = remote("router", "sysctl", "-n", "net.ipv6.conf.all.forwarding").stdout.strip()
    if forwarding != b"1":
        raise RuntimeError("Router IPv6 forwarding is disabled; subnet traffic cannot reach the VPC")
    wait_connected()
    probe_http("client", addrs["origin"])
    probe_http("client", addrs["origin"], 8081, allowed=False)
    remote("client", "ping", "-6", "-c", "3", "-W", "3", addrs["origin"])
    upload("client", [(Path(__file__), "staging-subnet-lab.py", 0o755)])
    remote("client", "python3", "/lab/staging-subnet-lab.py", "udp", "--address", addrs["origin"])
    print("PASS: private VPC HTTP, UDP (0..1232 bytes), ICMP; live TCP/UDP unapproved ports denied", flush=True)
    received = remote("origin", "cat", "/lab/received.jsonl").stdout.decode()
    rows = [json.loads(row) for row in received.splitlines()]
    assert rows and all(row["source"] == addrs["router"] for row in rows), rows
    assert not any(row["port"] in (8081,5354) for row in rows), rows
    statuses = {role: cli(role, "status") for role in ("router", "client")}
    for role, status in statuses.items():
        network = attachment(status)
        assert network["delivery_mode"] == "quic_datagram"
        assert network["packets_sent"] > 0 and network["packets_received"] > 0
        args.artifacts.mkdir(parents=True, exist_ok=True)
        (args.artifacts/(role+"-status.json")).write_text(json.dumps(status, indent=2))
        log = remote(role, "tail", "-n", "500", "/lab/daemon.log").stdout
        (args.artifacts/(role+"-daemon.log")).write_bytes(log)
        identity = python(role, "import json; p=open('/lab/daemon.pid').read().strip(); lines=open('/proc/'+p+'/status').read().splitlines(); v={s.split(':',1)[0]:s.split(':',1)[1].strip() for s in lines if s.startswith(('Uid:','CapEff:'))}; assert v['Uid'].split()==['1000']*4 and int(v['CapEff'],16)==0,v; print(json.dumps(v))").stdout
        (args.artifacts/(role+"-identity.json")).write_bytes(identity)
    (args.artifacts/"origin-received.jsonl").write_text(received)
    print("PASS: origin sees only router's VPC address (SNAT); bidirectional QUIC DATAGRAM; daemons are UID 1000 with no effective capabilities", flush=True)
    cli("client", "leave", NETWORK)
    time.sleep(2)
    probe_http("client", addrs["origin"], allowed=False)
    routes = json.loads(remote("client", "ip", "-j", "-6", "route").stdout)
    assert not any(row.get("dst") == PREFIX for row in routes)
    print("PASS: leaving removes client subnet route and access fails", flush=True)
    cli("router", "leave", NETWORK)
    for role in ("router", "client"):
        cli(role, "join", NETWORK)
    wait_connected()
    probe_http("client", addrs["origin"])
    print("PASS: explicit rejoin restores subnet access", flush=True)


def origin():
    import http.server
    import socketserver
    import threading
    def record(source, port, length):
        with open("/lab/received.jsonl", "a") as f:
            f.write(json.dumps(dict(source=source,port=port,length=length))+"\n")
    class HTTP(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            record(self.client_address[0],self.server.server_port,0)
            body=b"staging-connect-subnet\n"
            self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    class Server(http.server.ThreadingHTTPServer): address_family=socket.AF_INET6
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data,sock=self.request; record(self.client_address[0],sock.getsockname()[1],len(data)); sock.sendto(data,self.client_address)
    class UDPServer(socketserver.ThreadingUDPServer): address_family=socket.AF_INET6
    for cls,handler,ports in ((Server,HTTP,(8080,8081)),(UDPServer,UDP,(5353,5354))):
        for port in ports:
            server=cls(("::",port),handler)
            threading.Thread(target=server.serve_forever,daemon=True).start()
    threading.Event().wait()


def udp(address):
    for port in (5353,5354):
        for payload in ([b"probe",b"",bytes(range(256))*4,bytes(1232)] if port==5353 else [b"denied"]):
            with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                for attempt in range(5):
                    sock.sendto(payload,(address,port))
                    try: result,_=sock.recvfrom(65535)
                    except socket.timeout:
                        if port==5354: break
                        if attempt==4: raise
                    else:
                        assert port==5353 and result==payload
                        break


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("deploy","enroll","upgrade","attach","test","origin","udp"))
    parser.add_argument("--credentials",type=Path)
    parser.add_argument("--binaries",type=Path,default=ROOT/"target/staging-subnet-bin")
    parser.add_argument("--artifacts",type=Path,default=ROOT/"target/staging-subnet-evidence")
    parser.add_argument("--address")
    parser.add_argument("--skip-origin", action="store_true", help="Reuse an already running lab origin")
    parser.add_argument("--roles", nargs="+", choices=("router", "client"), default=("router", "client"), help="Deploy only the selected devices when resuming a partial deployment")
    parser.add_argument("--kubectl-context", help="Explicit alternative management transport; does not change Connect data path")
    parser.add_argument("--namespace", help="Exact staging namespace for the alternative transport")
    args=parser.parse_args()
    if bool(args.kubectl_context) != bool(args.namespace): parser.error("supply both --kubectl-context and --namespace")
    if args.kubectl_context: MANAGEMENT=(args.kubectl_context,args.namespace)
    if args.action in ("deploy","enroll","upgrade","attach","test"):
        identity = subprocess.run(["datumctl","whoami"],capture_output=True,text=True,check=True,timeout=30).stdout
        assert "Endpoint:     api.staging.env.datum.net" in identity, "Select the staging session first"
    if args.action=="origin": origin()
    elif args.action=="udp": udp(args.address)
    elif args.action=="deploy":
        if not args.credentials: parser.error("deploy requires --credentials")
        deploy(args)
    elif args.action=="enroll": enroll(args)
    elif args.action=="upgrade": upgrade(args)
    elif args.action=="attach": attach(args)
    else: test(args)
