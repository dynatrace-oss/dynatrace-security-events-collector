# Requirements

Before you begin, ensure you have the following prerequisites in place.

## Kubernetes cluster

- A running Kubernetes cluster (v1.26+)
- `kubectl` configured with access to create ClusterRole/ClusterRoleBinding resources
- Helm 3 installed

## Kyverno

Install Kyverno with OpenReports enabled. Minimum Helm values:

```yaml
openreports:
  enabled: true
  installCrds: true
```

To determine which policy types to deploy, see [Kyverno policy types](https://kyverno.io/docs/policy-types/).

## OpenTelemetry Operator

The [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator) must be installed in your cluster. It manages the `OpenTelemetryCollector` Custom Resource.

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm install opentelemetry-operator open-telemetry/opentelemetry-operator \
  --namespace opentelemetry-operator-system --create-namespace
```

## RBAC

The collector needs read access to OpenReports CRDs and core Kubernetes resources for enriching events with workload context. **Cluster-admin is not required** — apply the following least-privilege ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: otelcontribcol
  labels:
    app: otelcontribcol
rules:
  # Prometheus metrics endpoint
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]

  # OpenReports CRDs (Kyverno reports-server)
  - apiGroups: ["openreports.io"]
    resources: ["reports", "clusterreports"]
    verbs: ["get", "list", "watch"]

  # Kyverno PolicyReports (wgpolicyk8s.io)
  - apiGroups: ["wgpolicyk8s.io"]
    resources: ["policyreports", "clusterpolicyreports"]
    verbs: ["get", "list", "watch"]

  # Core resources (for K8s context enrichment)
  - apiGroups: [""]
    resources:
      - events
      - namespaces
      - namespaces/status
      - nodes
      - nodes/spec
      - nodes/stats
      - nodes/proxy
      - pods
      - pods/status
      - replicationcontrollers
      - replicationcontrollers/status
      - resourcequotas
      - services
      - endpoints
    verbs: ["get", "list", "watch"]

  # Events API
  - apiGroups: ["events.k8s.io"]
    resources: ["events"]
    verbs: ["watch"]

  # Workload resources (for workload name/kind enrichment)
  - apiGroups: ["apps"]
    resources: ["daemonsets", "deployments", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["extensions"]
    resources: ["daemonsets", "deployments", "replicasets"]
    verbs: ["get", "list", "watch"]

  # Batch resources
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch"]

  # Autoscaling resources
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch"]
```

Bind it to the collector's ServiceAccount:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-events-collector
  namespace: dynatrace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: otelcontribcol
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: otelcontribcol
subjects:
  - kind: ServiceAccount
    name: security-events-collector
    namespace: dynatrace
```

## Permissions

| Permission | Who needs it | Purpose |
|---|---|---|
| Dynatrace Admin | Token creator | Generate an API token with the required scopes |
| `storage:security.events:read` | Data consumers | Query ingested security events in Notebooks, Investigations, or Dashboards |
| ClusterRole/ClusterRoleBinding create | Deployer | Apply RBAC resources and deploy the collector |

## Tokens

Generate a Dynatrace access token with the following scopes:

| Token scope | Required | Purpose |
|---|---|---|
| `securityEvents.ingest` | **Yes** | Ingest security events via `/platform/ingest/v1/security.events` |
| `metrics.ingest` | Optional | Send OTLP metrics to Dynatrace |
| `logs.ingest` | Optional | Send OTLP logs to Dynatrace |
| `openTelemetryTrace.ingest` | Optional | Send OTLP traces to Dynatrace |

### How to generate the token

1. In Dynatrace, go to **Settings > Access Tokens**.
2. Select **Generate new token**.
3. Name it, e.g., `Kyverno Security Events Ingest`.
4. Select the required scopes (at minimum: `securityEvents.ingest`).
5. Select **Generate token** and copy the value immediately.

!!! warning
    The token is only shown once. Copy it immediately after generation. If lost, generate a new one.

For details, see [Dynatrace API — Tokens and authentication](https://docs.dynatrace.com).
