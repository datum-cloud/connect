# Architecture Diagrams

Structural architecture diagrams use
[C4-PlantUML](https://github.com/plantuml-stdlib/C4-PlantUML) and the Datum Cloud
theme from `datum-cloud/enhancements`. The theme is vendored as
[`datum-theme.puml`](./datum-theme.puml) so this documentation does not depend on
a sibling checkout.

| Diagram | C4 level | Used by |
| --- | --- | --- |
| `system-overview` | System context | Architecture overview |
| `deployment-topology` | Deployment | Architecture overview and deployment topology |
| `client-device` | Container | Client device architecture |
| `managed-gateway` | Container | Connect Gateway architecture |

Markdown embeds the committed PNGs. Edit the corresponding `.puml` source and
render it from the repository root:

```sh
plantuml -checkonly -failfast2 \
  docs/diagrams/system-overview.puml \
  docs/diagrams/deployment-topology.puml \
  docs/diagrams/client-device.puml \
  docs/diagrams/managed-gateway.puml

plantuml -tpng \
  docs/diagrams/system-overview.puml \
  docs/diagrams/deployment-topology.puml \
  docs/diagrams/client-device.puml \
  docs/diagrams/managed-gateway.puml
```

The C4 standard-library includes are resolved from their upstream repository at
render time. Sequence diagrams remain inline Mermaid where ordering matters
more than structural or deployment boundaries.
