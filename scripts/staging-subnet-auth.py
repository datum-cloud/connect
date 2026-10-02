#!/usr/bin/env python3
"""Create an expiring, project-scoped lab identity without exposing credentials.

Uses the caller's existing datumctl permissions, never controller credentials.
Private generated credentials stay outside the checkout and are printed only as
a path. This does not alter the caller's login session.
"""
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAME = "connect-subnet-lab"
PROJECT = "datum-cloud"


def call(args, body=None):
    result = subprocess.run(["datumctl", *args], input=None if body is None else json.dumps(body),
                            text=True, capture_output=True, check=False, timeout=45)
    if result.returncode:
        # Never include a key creation response, request, or credential in errors.
        raise RuntimeError(f"datumctl {' '.join(args[:3])} failed (exit {result.returncode}): {result.stderr[:1000]}")
    return json.loads(result.stdout)


def main():
    identity = subprocess.run(["datumctl", "whoami"], text=True, capture_output=True, check=True, timeout=30).stdout
    assert "Endpoint:     api.staging.env.datum.net" in identity, "Select your staging session before creating lab credentials"
    project = call(["get", "project", PROJECT, "--platform-wide", "-o", "json"])
    sa_manifest = {
        "apiVersion": "iam.miloapis.com/v1alpha1", "kind": "ServiceAccount",
        "metadata": {"name": NAME, "labels": {"connect.datum.net/lab": "subnet-20261002"}},
        "spec": {"state": "Active"},
    }
    sa = call(["get", "serviceaccount", NAME, "--project", PROJECT, "-o", "json", "--ignore-not-found"]) if "--resume" in __import__("sys").argv else call(["create", "--project", PROJECT, "-f", "-", "-o", "json"], sa_manifest)
    binding = {
        "apiVersion": "iam.miloapis.com/v1alpha1", "kind": "PolicyBinding",
        "metadata": {"name": NAME, "namespace": "milo-system", "labels": {"connect.datum.net/lab": "subnet-20261002"}},
        "spec": {
            "roleRef": {"name": "networking.datumapis.com-connector-admin", "namespace": "milo-system"},
            "subjects": [{"kind": "ServiceAccount", "name": NAME, "uid": sa["metadata"]["uid"]}],
            "resourceSelector": {"resourceRef": {"apiGroup": "resourcemanager.miloapis.com", "kind": "Project", "name": PROJECT, "uid": project["metadata"]["uid"]}},
        },
    }
    if "--resume" in __import__("sys").argv:
        existing=call(["get","policybinding",NAME,"--platform-wide","-n","milo-system","-o","json"])
        assert existing["spec"] == binding["spec"], "Existing lab binding has changed; refusing adoption"
    else:
        call(["create", "--platform-wide", "-n", "milo-system", "-f", "-", "-o", "json"], binding)
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    key = call(["create", "--project", PROJECT, "--validate=false", "-f", "-", "-o", "json"], {
        "apiVersion": "identity.miloapis.com/v1alpha1", "kind": "ServiceAccountKey",
        "metadata": {"name": NAME},
        "spec": {"serviceAccountUserName": f"{NAME}@{PROJECT}.identity.miloapis.com", "expirationDate": expires},
    })
    credentials = json.loads(key["status"]["privateKey"])
    credentials.update(project_id=PROJECT, api_endpoint="https://api.staging.env.datum.net", token_uri="https://auth.staging.env.datum.net/oauth/v2/token")
    path = Path(tempfile.mkdtemp(prefix="connect-subnet-lab-auth-")) / "credentials.json"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(credentials, stream)
    print(f"Created {NAME}; Connector Admin restricted to project {PROJECT}; key expires {expires}.")
    print(f"Key ID for cleanup: {key['metadata']['name']}")
    print(f"Private credentials: {path}")


if __name__ == "__main__":
    main()
