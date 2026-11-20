# Managed service admission bootstrap

Milo stores CRD definitions globally; Project APIs store resource instances.
The opt-in `../crd` export contains exactly ConnectEndpoint and ConnectGrant,
with Project discovery annotations. Discovery neither grants nor confines access.
Do not attempt to install these definitions or Kubernetes RoleBindings through
a Project API. The default customer export does not install these definitions.

## Ordered rollout

Keep managed provisioning disabled until every gate below passes. Infra owns
live configuration and resource writes.

1. Install this policy and its Deny binding into core Milo. All four variables
   default to `UNCONFIGURED`, denying managed writes. Do not add selectors or
   exclude status subresources. Confirm the deployed server supports native
   ValidatingAdmissionPolicy and reports no type-check warnings.
2. Install the core-global `../crd` definitions and `../iam` ProtectedResources
   and unbound roles. Never add these permissions to customer roles. A broad
   preexisting inherited IAM grant is also a rollout blocker, not an exception.
3. Establish supported Milo IAM ServiceAccount authentication. Verify the
   observed token username and UID and the deployed authenticator-to-OpenFGA
   subject mapping before binding permissions. A nonempty UID alone is not
   proof. Do not use an mTLS organization/group binding or fabricate a UID.
4. Bind the writer role only to the exact service Project resource incarnation
   and exact ServiceAccount incarnation. Bind the endpoint GET-only reader role
   separately for Certificates and the trusted probe. No PolicyBindings are
   supplied by this export. Establish renewable runtime credentials, not a
   hardcoded access token. Never print keys or tokens in qualification output.
5. Patch `serviceProject`, `serviceNamespace`, `writer`, and `writerUID` CEL
   string expressions from observed configuration. All must be nonempty and
   not `UNCONFIGURED`. The writer requires exact username AND UID. ServiceAccount
   recreation requires explicit requalification and configuration, not name reuse.
6. Run direct API authorization checks before enabling provisioning: authorized
   service-Project reconcile, status, retirement and retained tombstones;
   unauthorized get/list/watch, create/update/patch/status/dry-run/delete in the
   customer and another Project, including identical namespace/object names.
   Verify ordinary caller headers, labels and spec fields cannot supply trusted
   Project context. Check all reader identities separately. Hidden discovery or
   a SubjectAccessReview alone does not qualify these gates.
7. Deploy the lifecycle-only Certificates reader before phase-less Connect
   writes. Keep frontend, probe and actual packet qualification as separate gates.

The admission policy denies DELETE, including deletecollection's per-object
deletion admission. No privileged retention exception is supplied. Future
retention/migration requires an explicitly reviewed procedure, proof of finished
external cleanup and preserved revocation history; it must not happen through an
accidental broad writer or policy exclusion.

## Trusted context and read boundary

Milo v0.32.1 `pkg/server/filters/projects.go` obtains the Project from request
context and overwrites `iam.miloapis.com/parent-{type,name,api-group}` in the
authenticated user's extras. `pkg/server/filters/utils.go` copies the supplied
user extras first, then overwrites them with server values. The filter chain in
`cmd/milo/apiserver/config.go` authenticates and authorizes impersonation before
the Project-context decorator. Ordinary object fields cannot manufacture this
context. Validate that the deployed source retains this ordering; authorized
impersonation remains a separate privileged boundary.

The policy requires singleton exact Project/type/API-group extras and the exact
configured namespace. Missing, wrong or ambiguous context fails closed. It does
not authorize GET, LIST or WATCH: Milo IAM must independently confine those
requests to the service Project. Native core RBAC with equal namespace/resource
names across Projects is not an accepted substitute without separate proof.

`failurePolicy: Fail` rejects evaluation errors. It cannot protect against a
privileged administrator removing the policy/binding. Protect those resources
and monitor their continued presence; missing enforcement blocks rollout.

## Test boundary

`TestManagedAdmissionDirectAPI` uses a real Kubernetes envtest API and the
exported native policy. A test-only RBAC grant deliberately permits all test
actors to reach admission, and privileged test impersonation supplies simulated
Milo context. The test covers default denial, exact writer/UID/context, direct
create/update/status, dry-run, tombstone retention and evaluation failure.
This RBAC grant is not exported or suitable for Milo deployment. These tests
do not prove live authentication, OpenFGA read confinement, or server context
provenance; the ordered live checks remain mandatory.
