# Identity and Authorization

Connect uses separate identities for the human or workload operating the
device, the Connector transport endpoint, callers of the local daemon, and a
managed gateway. Keeping those identities distinct limits what a compromise at
one boundary can authorize.

## Identity Types

| Identity | Stored where | Used for |
| --- | --- | --- |
| Datum user or service account | Host session reference or protected credential file | Project API authorization |
| Connector keypair | Private daemon repository; public key in `Connector` | Peer authentication and stable device identity |
| Daemon bearer token | Secret presented locally; salted hash in daemon state | Loopback API roles and scopes |
| Gateway keypair | Project Secret mounted read-only in Workload | Gateway endpoint authentication |
| Networking-helper peer credentials | Protected local helper configuration and IPC | Authorize one user daemon and bounded adapter plans |

No Connector private key is stored in the project API. Gateway status exposes
only the public endpoint ID. The networking helper has no cloud credentials or
Connector key.

## Cloud Credentials

Interactive enrollment pins a `datumctl` session identifier, not its access or
refresh token. The daemon invokes `datumctl auth get-token` to refresh access
using that session. `up --auth oidc` explicitly replaces stored authorization;
`up --auth stored` reuses it.

Service deployments use an imported credential file. The daemon validates the
source, copies it into private storage, and no longer depends on the original
path. Root/system daemons must use file-based credentials; a user's interactive
OIDC session is never passed to a privileged service.

## Local Daemon Roles

The loopback API accepts bearer tokens with three roles:

| Role | Purpose |
| --- | --- |
| `setup` | Initial full-control bootstrap token kept in protected service state |
| `operate` | Delegated mutations limited to one project and optional resource scopes |
| `viewer` | Read-only project status and diagnostics |

Operate tokens may be scoped to the whole project or to a specific
`service:<id>` or `dial:<port>`. Status output for a resource-scoped operator
omits Connector, authentication, transport, and network details outside that
scope. The daemon stores a salted hash, supports expiry and revocation, and
keeps a bounded mutation audit trail.

The API client accepts only `localhost` or literal loopback addresses. Loopback
reduces exposure but does not replace token authentication. Request and
authorization bodies are never written to diagnostic logs.

## Authorization Boundaries

| Action | Required authority |
| --- | --- |
| Enroll or refresh a Connector | Datum principal authorized in the project |
| Advertise a service | Owner of the enrolled Connector and matching local daemon scope |
| Reach a private service | Serving Connector policy resolves caller key as approved |
| Create public ingress | Explicit `--public` plus permission to create the owned HTTPProxy |
| Join a managed VPC | Permission to create or reuse the project `ConnectNetworkBinding` |
| Enter a managed gateway | Authenticated Connector key present in the applied grant |
| Install address and routes | Exact peer approval or administrator-approved managed-client policy |
| Route direct-peer packets | Explicit protocol and direction rules on both operators' configuration |

Authorization is checked at multiple layers intentionally. A binding without a
gateway grant, a grant without the matching Connector key, or a session without
local helper approval is insufficient on its own.

## Pinning and Ownership

Connector names resolve to public keys when a service allowlist, dial, or peer
binding is created. Saved intent uses the key. Cloud resources created by the
daemon carry the Connector owner label and owner reference; reconciliation
refuses to overwrite a foreign object or an administrator-edited incompatible
specification.

Deleting the Connector is an immediate revocation boundary. Refresh does not
silently recreate a deleted Connector. Current key rotation requires resource
replacement and is not yet a production-grade lifecycle.

## Secret Handling

Private state and credentials use owner-restricted files, reject unsafe file
types, and are replaced atomically. Windows additionally requires protected
ACLs and rejects reparse points. Networking configuration files and driver
artifacts are pinned and validated before privileged use.

## Related Documentation

- [Enrollment and Reconciliation](./enrollment-and-reconciliation.md)
- [Multi-Tenancy](./multi-tenancy.md)
- [Network Helper Architecture](../components/network-helper-architecture.md)
- [Headless preview validation](../headless-preview.md)
