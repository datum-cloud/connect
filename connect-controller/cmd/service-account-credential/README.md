# Renewable Milo service account credentials

The Connect image contains `/service-account-credential`, a client-go exec v1
credential plugin. It exchanges a fresh RS256 JWT assertion for a bearer token
using the verified Milo/Zitadel service-account flow. Keys never enter command
arguments or logs; stdout is exclusively the private ExecCredential response.
Do not run the exchange command interactively or capture stdout into CI logs.

Mount an operator-owned private configuration file and RSA key (2048 bits or
larger, PKCS#1 or PKCS#8 PEM). Configuration example with deliberately unset
identity and lifetime values:

```json
{
  "tokenURL": "https://auth.staging.env.datum.net/oauth/v2/token",
  "audience": "325848900940337178",
  "subject": "OBSERVED_SERVICE_ACCOUNT_UID",
  "keyID": "REGISTERED_PUBLIC_KEY_ID",
  "privateKeyPath": "/private/service-account/key.pem",
  "keyExpiresAt": "REPLACE_WITH_ACTUAL_KEY_EXPIRATION_RFC3339"
}
```

Resolve identity through actual authenticated whoami and verify the UID maps to
the scoped OpenFGA ServiceAccount subject. Different controller, probe and
Certificates reader identities require different credentials and IAM grants.
This helper grants no authorization and does not create or rotate account keys.
Operators must rotate the registered key and mounted configuration before expiry.

The JWT has `iss=sub=subject`, `aud` equal to the token endpoint's HTTPS origin,
`iat=now`, `exp=now+60s`, random UUID `jti`, and RS256 header `kid`/`typ=JWT`.
The POST uses `urn:ietf:params:oauth:grant-type:jwt-bearer` and scope
`openid profile email urn:zitadel:iam:org:project:id:<audience>:aud`.
TLS uses normal certificate validation; redirects and proxy environment routing
are disabled. Configuration must use the independently verified token endpoint.
No insecure-TLS override or static bearer fallback is supported.

Configure each consumer kubeconfig user:

```yaml
user:
  exec:
    apiVersion: client.authentication.k8s.io/v1
    command: /service-account-credential
    args: [--config=/private/service-account/config.json]
    interactiveMode: Never
    provideClusterInfo: false
```

Do not include `token`, `tokenFile`, or client certificate authentication in this
user. Keep the API server CA and exact selected Project URL in its cluster entry.
Client-go caches the result for at most five minutes (shorter token/key lifetimes
win, with expiry margin), then executes the helper again. A failed exchange
returns no credential, and expired exec cache is not reused. Errors intentionally
exclude response bodies/assertions/keys/tokens. Responses without explicit bounded
Bearer expiry are rejected; the current maximum accepted token lifetime is 24h.

**Five minutes bounds the local exec cache, not the issued bearer lifetime.**
An issued token can remain cryptographically valid for the issuer's advertised
lifetime (observed staging response: 43199 seconds). Refresh or key expiry does
not revoke already-open watches. Actual authorization revocation and watch
termination are separate server responsibilities; do not claim five-minute
revocation or treat this mechanism as endpoint credential revocation.

For images without the helper (including Certificates), use an initContainer
from the exact qualified Connect image with command:

```yaml
command: [/service-account-credential]
args: [--install-to=/credential-bin/service-account-credential]
```

Share only that emptyDir with the consumer, mounted read-only there, and use
`/credential-bin/service-account-credential` as its exec command. The installer
atomically copies its static platform-matching binary at mode 0555. Configure a
nonroot writable shared volume using an explicit pod fsGroup; do not escalate
the initContainer to root. Mount private credentials only into the consumer,
not the installer. Preserve existing workload flags, volumes and credentials.

Tests verify TLS, exact signed claims, fresh assertion nonces, bounded expiry,
malformed responses, redirect rejection and secret-free errors. A real client-go
exec subprocess test verifies that refresh failure after expiry sends no API
request with the old bearer. These are not live OpenFGA confinement tests.
