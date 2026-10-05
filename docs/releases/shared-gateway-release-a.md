# Shared gateway Release A

Release A moves managed `/128` CONNECT-IP attachments from tenant-created
gateway workloads toward an operator-managed, multi-tenant gateway pool. It
does not add routed customer prefixes, prefix translation, or Galactic
dataplane programming.

## Control-plane model

- `ConnectGatewayPool` is cluster-scoped operator configuration. It declares a
  location and one or more shared iroh gateway endpoints.
- A project `ConnectGateway` with `spec.poolRef` is a logical VPC attachment.
  The controller selects a stable pool endpoint with rendezvous hashing and
  does not create a Secret, ConfigMap, or Compute Workload in the project.
- `ConnectNetworkBinding.status.bindingID` is derived from the project cluster
  identity and the binding UID. The daemon uses it as the CONNECT-IP network
  selector, so admission is keyed by `(authenticated Connector key, bindingID)`
  rather than a reusable network name.
- The existing single-address `/128`, explicit VPC routes, helper approval, and
  persistent managed-join behavior remain unchanged.

The legacy per-VPC Workload path remains available when `poolRef` is empty so
the API change can be rolled out independently of the shared dataplane.

## Fail-closed boundary

Endpoint assignment alone does not prove that a shared gateway installed the
binding. Shared bindings therefore remain `Accepted=Unknown` with reason
`GatewayAdmissionPending`. The next slice must define a serving-cell resource
or authenticated control stream that carries the binding ID, Connector public
key, VPC identity, `/128` pair, routes, and selected endpoint, plus an
acknowledgement observed by this controller. Only that acknowledgement may set
`Accepted=True`.

The cross-cluster transport and Galactic VRF attachment are intentionally not
invented in this repository. They require an agreed ownership and fencing
contract with the serving-cell and Galactic controllers.

## Next slice

1. Define the serving-cell admission API and status acknowledgement.
2. Replicate each resolved binding to the selected gateway instance.
3. Make the gateway hot-add and revoke grants keyed by Connector key and
   binding ID.
4. Set `Accepted=True` only after the selected instance reports the exact
   binding generation installed.
5. Add reconnect and revocation integration tests around managed `join`.
