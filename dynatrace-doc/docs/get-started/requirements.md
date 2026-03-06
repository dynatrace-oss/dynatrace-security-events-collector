<div class="dt-breadcrumb">
  <a href="..">Home</a> &rsaquo; Get started &rsaquo; Requirements
</div>

# Requirements

Before you begin, ensure you have the following prerequisites in place.

## Kubernetes cluster

- A running Kubernetes cluster (v1.26+)
- `kubectl` configured with cluster admin access
- Helm 3 installed

## Kyverno

Install Kyverno with OpenReports enabled. You need the following Helm values at minimum:

```yaml
openreports:
  enabled: true
  installCrds: true
```

To determine which policy types to deploy, see [Kyverno policy types](https://kyverno.io/docs/policy-types/).

## OpenTelemetry Operator

The [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator) must be installed in your cluster. It manages the `OpenTelemetryCollector` Custom Resource used by this integration.

```bash
# Install via Helm
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm install opentelemetry-operator open-telemetry/opentelemetry-operator \
  --namespace opentelemetry-operator-system --create-namespace
```

## Permissions

| Permission | Who needs it | Purpose |
|---|---|---|
| Dynatrace Admin | Token creator | Generate an API token with the required scopes |
| `storage:security.events:read` | Data consumers | Query ingested security events in Notebooks, Investigations, or Dashboards |
| Kubernetes cluster-admin | Deployer | Apply RBAC resources and deploy the collector |

## Tokens

Generate a Dynatrace access token with the following scopes:

| Token scope | Required | Purpose |
|---|---|---|
| `securityEvents.ingest` | **Yes** | Ingest security events via `/platform/ingest/v1/security.events` |
| `metrics.ingest` | Optional | Send OpenTelemetry metrics to Dynatrace via OTLP |
| `logs.ingest` | Optional | Send OpenTelemetry logs to Dynatrace via OTLP |
| `openTelemetryTrace.ingest` | Optional | Send OpenTelemetry traces to Dynatrace via OTLP |

### How to generate the token

1. In Dynatrace, go to **Settings → Access Tokens**.
2. Select **Generate new token**.
3. Name it, e.g., `Kyverno Security Events Ingest`.
4. Select the required scopes (at minimum: `securityEvents.ingest`).
5. Select **Generate token** and copy the value immediately.

!!! warning
    The token is only shown once. Copy it immediately after generation. If lost, generate a new one.

For details, see [Dynatrace API — Tokens and authentication](https://docs.dynatrace.com).
