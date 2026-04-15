<div class="dt-breadcrumb">
  Dynatrace &rsaquo; How-to guide
</div>

# Ingest Kyverno policy compliance findings and security events

<span class="dt-badge dt-badge--grail">Grail security events</span>
<span class="dt-badge dt-badge--guide">How-to guide</span>
<span class="dt-badge dt-badge--version">Latest Dynatrace</span>

---

!!! note "Grail security events table"
    This page is aligned with the new Grail security events table. For the complete list of updates and actions needed to accomplish the migration, follow the steps in the [Grail security table migration guide](https://docs.dynatrace.com).

Ingest Kubernetes policy compliance findings and security events from **Kyverno** into Grail and analyze them in Dynatrace.

## Get started

### Overview

In the following, you'll learn how to ingest policy compliance findings and security events from [Kyverno](https://kyverno.io/) into Grail and analyze them on the Dynatrace platform, so you can gain insights into Kubernetes policy compliance posture and easily work with your data.

Kyverno is a Kubernetes-native policy engine that validates, mutates, and generates resource configurations. When policies are deployed in a cluster, Kyverno evaluates every targeted resource and produces **OpenReports** — standardized compliance reports describing whether each resource passes or fails each policy rule.

This integration collects those OpenReports using a custom OpenTelemetry Collector distribution, transforms them into Dynatrace security events, and delivers them to the Dynatrace Security Events Ingest API.

### Use cases

With the ingested data, you can accomplish various use cases, such as:

- Visualize and analyze policy compliance findings across clusters
- Track non-compliant resources by severity (Critical, High, Medium, Low)
- Automate and orchestrate remediation workflows for policy violations
- Correlate Kyverno findings with other Dynatrace security data
- Monitor compliance drift over time with dashboards

### Requirements

- **Kyverno** installed in your Kubernetes cluster with OpenReports enabled. See [Requirements](get-started/requirements.md).
- **OpenTelemetry Operator** installed in your cluster. See [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator).
- **kubectl** configured with cluster access.
- **Helm 3** installed.
- **Permissions:**
    - You need a Dynatrace Admin user to generate the required API token.
    - To query ingested data: `storage:security.events:read`.
- **Tokens:**
    - Generate an access token with the **`securityEvents.ingest`** scope and save it for later. For details, see [Dynatrace API — Tokens and authentication](https://docs.dynatrace.com).
    - If you also send metrics, logs, or traces, add the `metrics.ingest`, `logs.ingest`, and `openTelemetryTrace.ingest` scopes respectively.

[Get started with setup :material-arrow-right:](get-started/overview.md){ .md-button .md-button--primary }
