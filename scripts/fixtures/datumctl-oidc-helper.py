#!/usr/bin/env python3
"""Fake datumctl credential helper for the isolated OIDC process E2E only."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys


root = Path(os.environ['TEST_DATUM_HELPER_DIR'])
state = json.loads((root / 'helper-state.json').read_text())
expected = ['auth', 'get-token', '--session', state['session'],
            '--output', 'client.authentication.k8s.io/v1']
with (root / 'helper-calls.jsonl').open('a') as log:
    log.write(json.dumps({'args': sys.argv[1:], 'generation': state['generation']}) + '\n')
if sys.argv[1:] != expected:
    print('fixture rejects unexpected arguments or session', file=sys.stderr)
    sys.exit(2)
if state.get('logged_out'):
    print('fixture session is logged out', file=sys.stderr)
    sys.exit(1)
expiration = datetime.now(timezone.utc) + timedelta(seconds=state.get('expiry_seconds', 5))
print(json.dumps({'apiVersion': 'client.authentication.k8s.io/v1', 'kind': 'ExecCredential',
                  'status': {'token': state['token'],
                             'expirationTimestamp': expiration.isoformat().replace('+00:00', 'Z')}}))
