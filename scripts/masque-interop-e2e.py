#!/usr/bin/env python3
"""Independent masque-go client -> standard H3 edge -> Connect service -> UDP echo."""

import argparse
import json
import os
from pathlib import Path
import socketserver
import subprocess
import tempfile
import threading
import time


class Echo(socketserver.BaseRequestHandler):
    packets = []

    def handle(self):
        payload, sock = self.request
        self.packets.append(payload)
        sock.sendto(b"udp:" + payload, self.client_address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--sessions", type=int, default=3)
    args = parser.parse_args()
    lab = args.lab.resolve()
    client = args.client.resolve()
    for binary in (lab, client):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"not an executable: {binary}")

    root = Path(tempfile.mkdtemp(prefix="datum-masque-interop-"))
    root.chmod(0o700)
    print(f"Artifacts: {root}", flush=True)
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    allowed = f"127.0.0.1:{echo.server_address[1]}"
    ready, cert = root / "ready.json", root / "ca.pem"
    log = (root / "lab.log").open("wb")
    process = subprocess.Popen(
        [str(lab), "--origin", allowed, "--cert-out", str(cert), "--ready-out", str(ready)],
        cwd=root,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not ready.exists():
            if process.poll() is not None:
                raise AssertionError(f"lab exited; inspect {root / 'lab.log'}")
            time.sleep(0.05)
        if not ready.exists():
            raise AssertionError(f"lab was not ready; inspect {root / 'lab.log'}")
        metadata = json.loads(ready.read_text())
        unauthenticated = [
            str(client),
            "-proxy", metadata["proxy_uri_template"],
            "-proxy-address", metadata["proxy_addr"],
            "-ca", str(cert),
        ]
        for credential_args in ([], ["-bearer-token", "invalid-staging-token"]):
            rejected = subprocess.run(
                [
                    *unauthenticated,
                    *credential_args,
                    "-target", allowed,
                    "-expect-status", "407",
                ],
                text=True,
                capture_output=True,
                timeout=20,
            )
            assert rejected.returncode == 0, rejected.stdout + rejected.stderr
            assert Echo.packets == [], Echo.packets
            print(rejected.stdout.strip(), flush=True)

        common = [
            *unauthenticated,
            "-bearer-token", metadata["bearer_token"],
        ]
        positive = subprocess.run(
            [
                *common,
                "-target", allowed,
                "-denied-target", metadata["denied_target"],
                "-payload", "datum-masque-e2e",
                "-sessions", str(args.sessions),
            ],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert positive.returncode == 0, positive.stdout + positive.stderr
        expected_packets = (
            [b"datum-masque-e2e"]
            if args.sessions == 1
            else [f"datum-masque-e2e-{i}".encode() for i in range(args.sessions)]
        )
        assert Echo.packets == expected_packets, Echo.packets
        print(positive.stdout.strip(), flush=True)

        fallback = subprocess.run(
            [
                *common,
                "-target", allowed,
                "-payload", "datum-capsule-fallback",
                "-capsule-fallback",
            ],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert fallback.returncode == 0, fallback.stdout + fallback.stderr
        assert Echo.packets == [*expected_packets, b"datum-capsule-fallback"], Echo.packets
        print(fallback.stdout.strip(), flush=True)
        connect_ip = subprocess.run(
            [
                str(client),
                "-proxy-address", metadata["proxy_addr"],
                "-ca", str(cert),
                "-ip-proxy", metadata["ip_uri"],
                "-bearer-token", metadata["bearer_token"],
                "-connect-ip",
            ],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert connect_ip.returncode == 0, connect_ip.stdout + connect_ip.stderr
        print(connect_ip.stdout.strip(), flush=True)
        denied_ip = subprocess.run(
            [
                str(client),
                "-proxy-address", metadata["proxy_addr"],
                "-ca", str(cert),
                "-ip-proxy", metadata["ip_uri"].replace("/*/*/", "/10.30.0.10/17/"),
                "-bearer-token", metadata["bearer_token"],
                "-connect-ip",
                "-expect-status", "403",
            ],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert denied_ip.returncode == 0, denied_ip.stdout + denied_ip.stderr
        print(denied_ip.stdout.strip(), flush=True)
        print("PASS standard H3 edge translated through the real Connect UDP transport", flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        echo.shutdown()
        echo.server_close()


if __name__ == "__main__":
    main()
