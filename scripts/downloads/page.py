#!/usr/bin/env python3
"""Renders and uploads the Datum Connect download page from the bucket's contents.

    scripts/downloads/page.py [--bucket datum-download] [--region us-east-2]

Reads latest.json for connect/android/, connect/linux/, and connect/macos/,
lists every published file under them, and writes
connect/index.html. connect/android/index.html becomes a redirect to it, so
older links keep working. The publish scripts run this after uploading;
running it alone just refreshes the page. Uses the AWS CLI and its usual
credentials (for example AWS_PROFILE=datum-sandbox-admin).
"""
import argparse
import html
import json
import pathlib
import subprocess
import sys
import tempfile

PREFIX = "connect"
LOGO = pathlib.Path(__file__).with_name("datum-logo.svg")


def aws(region, *args, quiet=False):
    return subprocess.check_output(
        ["aws", "--region", region, *args], text=True,
        stderr=subprocess.DEVNULL if quiet else None,
    )


def latest(bucket, region, platform):
    try:
        # A platform with nothing published yet has no latest.json.
        return json.loads(aws(region, "s3", "cp", f"s3://{bucket}/{PREFIX}/{platform}/latest.json", "-", quiet=True))
    except subprocess.CalledProcessError:
        return None


def published(bucket, region, platform, suffix):
    """Every published file for a platform with its metadata, newest first."""
    listing = json.loads(aws(
        region, "s3api", "list-objects-v2", "--bucket", bucket,
        "--prefix", f"{PREFIX}/{platform}/datum-connect-",
        "--query", "Contents[].[Key,Size,LastModified]", "--output", "json",
    ) or "null") or []
    files = []
    for key, size, modified in listing:
        if not key.endswith(suffix):
            continue
        meta = json.loads(aws(
            region, "s3api", "head-object", "--bucket", bucket, "--key", key,
            "--query", "Metadata", "--output", "json",
        )) or {}
        files.append({"key": key, "name": key.rsplit("/", 1)[1], "size": size, "modified": modified, "meta": meta})
    files.sort(key=lambda f: (f["meta"].get("built", ""), f["modified"]), reverse=True)
    return files


def e(value):
    return html.escape(str(value))


def mb(size):
    return f"{max(1, round(size / 1048576))} MB"


def day(yyyymmdd):
    return f"{yyyymmdd[:4]}-{yyyymmdd[4:6]}-{yyyymmdd[6:]}" if len(yyyymmdd) == 8 else yyyymmdd


def android_section(apk):
    if not apk:
        return ""
    return f"""
<h2>Android</h2>
<p>Open a shared service on your phone. Scan the QR code from a computer, then tap <b>Open</b>.</p>
<p><a class="btn" href="android/{e(apk['name'])}">Download APK ({mb(apk.get('size', 0))})</a></p>
<p><small>Built {day(apk['built'])}, version <code>{e(apk['versionName'])}</code>. Android 10 or later.
Allow installs from your browser when Android asks.<br>
SHA-256 <code>{e(apk['sha256'])}</code><br>
Signing certificate SHA-256 <code>{e(apk['signingCertSha256'])}</code></small></p>
"""


CLI = {
    "linux": {
        "title": "Linux",
        "needs": "Needs glibc 2.34 or later and OpenSSL 3: Ubuntu 22.04, Debian 12, Fedora 36, or newer.",
        "note": "",
    },
    "macos": {
        "title": "macOS",
        "needs": "Needs macOS 12 or later.",
        "note": """<p><small>These binaries are not notarized. Download them with <code>curl</code> as shown;
a browser download is quarantined and macOS refuses to run it. If that happens, run
<code>xattr -d com.apple.quarantine datumctl-connect datum-connectd</code> in the extracted folder.</small></p>
""",
    },
}


def cli_section(platform, build, base, others_missing):
    if not build:
        return ""
    info = CLI[platform]
    rows = []
    for f in build["files"]:
        rows.append(f"""<li><a href="{platform}/{e(f['name'])}">{e(f['name'])}</a> ({mb(f['size'])})
<br><small>{e(f['label'])}<br>SHA-256 <code>{e(f['sha256'])}</code></small></li>""")
    example = build["files"][0]
    coming = " ".join(f"{CLI[p]['title']} builds are coming." for p in others_missing)
    return f"""
<h2>{info['title']}</h2>
<p>The <code>datumctl-connect</code> command line, with the <code>datum-connectd</code> agent it runs.
Use it on its own, as below, or as a <code>datumctl</code> plugin.</p>
<ul class="files">
{''.join(rows)}
</ul>
<p><small>Built {day(build['built'])}, version <code>{e(build['version'])}</code>.
{info['needs']} {coming}</small></p>
<pre><code>curl -fsSLO {e(base)}/{platform}/{e(example['name'])}
tar xzf {e(example['name'])}
cd {e(example['dir'])}
./datumctl-connect --help</code></pre>
{info['note']}<p><small>Already use <code>datumctl</code>? Copy both binaries into <code>~/.datumctl/plugins/</code>
and run <code>datumctl connect local</code> instead of <code>./datumctl-connect local</code>.</small></p>
"""


PAIRING = """
<h2>Make a tunnel between two devices</h2>
<p>One device shares a local service. The other pairs with it and gets that service on its own
<code>localhost</code>. Traffic is end-to-end encrypted over <a href="https://www.iroh.computer/">iroh</a>,
directly between the devices when the network allows and through a public relay when it doesn't.
No Datum account or login is needed.</p>
<ol>
<li><p><b>On the computer with the service</b>, for example a web app on port 8080:</p>
<pre><code>./datumctl-connect local --port 8080 --name "my app"</code></pre>
<p>It prints a QR code, a ticket, and a ready-to-run dial command, and waits.</p></li>
<li><p><b>On an Android phone:</b> in Datum Connect, tap <b>Scan QR code</b>, then <b>Connect</b>
and <b>Open</b>.</p>
<p><b>Or on another computer:</b> run the printed command, then open
<code>http://localhost:8080</code>:</p>
<pre><code>./datumctl-connect dial DCSHARE2… --bind 8080</code></pre></li>
<li><p>Press Ctrl+C on the sharing computer to end the share. Every run prints a new ticket.</p></li>
</ol>
<p><small>Anyone with the ticket can connect, up to <code>--max-peers</code> devices (default 4),
until the share stops. The ticket also contains the sharing computer's IP addresses, so send it
only to people you trust.</small></p>
"""


def past_section(files):
    if not files:
        return ""
    items = []
    for f in files:
        meta = f["meta"]
        details = [f"Built {day(meta['built'])}" if meta.get("built") else None,
                   f"version <code>{e(meta['version-name'])}</code>" if meta.get("version-name") else None]
        sha = f"<br>SHA-256 <code>{e(meta['sha256'])}</code>" if meta.get("sha256") else ""
        items.append(f"""<li><a href="{e(f['href'])}">{e(f['name'])}</a> ({mb(f['size'])})
<br><small>{', '.join(d for d in details if d)}{sha}</small></li>""")
    return f"""
<h2>Past builds</h2>
<p><small>Older builds stay available. Android installs one over a newer build only after you uninstall it.</small></p>
<ul class="files">
{''.join(items)}
</ul>
"""


def page(apk, cli, past, base):
    logo = "\n".join(line for line in LOGO.read_text().splitlines() if not line.startswith("<!--"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datum Connect downloads</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:ui-sans-serif,system-ui,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol','Noto Color Emoji';margin:1.25rem;line-height:1.5;max-width:40rem}}
header{{margin:.5rem 0 1.5rem}}
header svg{{display:block;height:28px;width:auto}}
h1,h2{{font-weight:600;letter-spacing:-.01em}}
h2{{font-size:1.25rem;margin-top:2.5rem}}
a.btn{{display:inline-block;font-size:1.1rem;padding:.7rem 1rem;border-radius:8px;background:#4f46e5;color:#fff;text-decoration:none}}
code{{overflow-wrap:anywhere}}
pre{{padding:.75rem;border-radius:6px;overflow-x:auto;background:color-mix(in srgb,currentColor 8%,transparent)}}
pre code{{overflow-wrap:normal}}
small{{opacity:.75}}
ol{{padding-left:1.25rem}}
ul.files{{list-style:none;padding:0;margin:0}}
ul.files li{{padding:.6rem 0;border-top:1px solid color-mix(in srgb,currentColor 20%,transparent);overflow-wrap:anywhere}}
</style></head>
<body>
<header><a href="https://www.datum.net/" style="color:inherit">{logo}</a></header>
<h1>Datum Connect</h1>
<p>Share a service running on one device with your other devices, without an account.</p>
{android_section(apk)}{cli_sections(cli, base)}{PAIRING}{past_section(past)}
</body></html>
"""


def cli_sections(cli, base):
    missing = [p for p in CLI if not cli.get(p)]
    # Mention missing platforms once, under the first published one.
    out, mentioned = [], False
    for platform in CLI:
        section = cli_section(platform, cli.get(platform), base, [] if mentioned else missing)
        if section:
            out.append(section)
            mentioned = True
    return "".join(out)


REDIRECT = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=../index.html">
<title>Datum Connect downloads</title></head>
<body><p>Moved to <a href="../index.html">Datum Connect downloads</a>.</p></body></html>
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bucket", default="datum-download")
    parser.add_argument("--region", default="us-east-2")
    args = parser.parse_args()
    base = f"https://{args.bucket}.s3.{args.region}.amazonaws.com/{PREFIX}"

    apk = latest(args.bucket, args.region, "android")
    cli = {platform: latest(args.bucket, args.region, platform) for platform in CLI}
    current = set()
    if apk:
        current.add(f"{PREFIX}/android/{apk['name']}")
        sizes = {f["name"]: f["size"] for f in published(args.bucket, args.region, "android", ".apk")}
        apk["size"] = sizes.get(apk["name"], 0)
    for platform, build in cli.items():
        if build:
            current.update(f"{PREFIX}/{platform}/{f['name']}" for f in build["files"])

    past = []
    for platform, suffix in (("android", ".apk"), *((p, ".tar.gz") for p in CLI)):
        for f in published(args.bucket, args.region, platform, suffix):
            if f["key"] not in current:
                f["href"] = f"{platform}/{f['name']}"
                if "built" not in f["meta"]:
                    # Names carry the build date: datum-connect[-platform-arch]-YYYYMMDD-<sha>.
                    f["meta"]["built"] = f["name"].rsplit("-", 2)[-2]
                past.append(f)
    past.sort(key=lambda f: (f["meta"].get("built", ""), f["modified"]), reverse=True)

    with tempfile.TemporaryDirectory() as work:
        index = pathlib.Path(work, "index.html")
        index.write_text(page(apk, cli, past, base))
        redirect = pathlib.Path(work, "redirect.html")
        redirect.write_text(REDIRECT)
        for path, key in ((index, f"{PREFIX}/index.html"), (redirect, f"{PREFIX}/android/index.html")):
            aws(args.region, "s3", "cp", str(path), f"s3://{args.bucket}/{key}",
                "--content-type", "text/html; charset=utf-8", "--cache-control", "no-cache", "--only-show-errors")
    print(f"Download page: {base}/index.html")


if __name__ == "__main__":
    sys.exit(main())
