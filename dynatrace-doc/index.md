# Ingest Kyverno policy compliance findings and security events

* Latest Dynatrace
* How-to guide
* Updated on Feb 20, 2026

This page is aligned with the new Grail security events table. For the complete list of updates and actions needed to accomplish the migration, follow the steps in the [Grail security table migration guide](https://docs.dynatrace.com).

Ingest Kubernetes policy compliance findings and security events from **Kyverno** into Grail and analyze them in Dynatrace.

---

## Get started

### Overview

In the following, you'll learn how to ingest policy compliance findings and security events from [Kyverno](https://kyverno.io/) into Grail and analyze them on the Dynatrace platform, so you can gain insights into Kubernetes policy compliance posture and easily work with your data.

Kyverno is a Kubernetes-native policy engine that validates, mutates, and generates resource configurations. When policies are deployed in a cluster, Kyverno evaluates every targeted resource and produces **OpenReports** — standardized compliance reports (`reports` and `clusterreports` in the `openreports.io` API group) describing whether each resource passes or fails each policy rule.

This integration collects those OpenReports using a custom OpenTelemetry Collector distribution equipped with two plugins — the **Security Event Processor** and the **Security Event Exporter** — that transform policy findings into Dynatrace security events and deliver them to the Security Events Ingest API.

### Use cases

With the ingested data, you can accomplish various use cases, such as

* Visualize and analyze policy compliance findings across clusters
* Track non-compliant resources by severity (Critical, High, Medium, Low)
* Automate and orchestrate remediation workflows for policy violations
* Correlate Kyverno findings with other Dynatrace security data

### Requirements

* **Kyverno** installed in your Kubernetes cluster with OpenReports enabled:
    * Set `openreports.enabled: true` and `openreports.installCrds: true` in the Kyverno Helm values.
    * Deploy at least one validating policy. See [Kyverno policy types that generate reports](#kyverno-policy-types-that-generate-reports).

* **OpenTelemetry Operator** installed in your cluster. See [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator).

* **kubectl** configured with cluster admin access.

* **Helm 3** installed.

* Permissions:
    * You need a Dynatrace **Admin** user to generate the required API token.
    * To query ingested data: `storage:security.events:read`.

* Tokens:
    * Generate an access token with the **`securityEvents.ingest`** scope and save it for later. For details, see [Dynatrace API — Tokens and authentication](https://docs.dynatrace.com).
    * If you also send metrics, logs, or traces via OTLP, add the corresponding scopes:

    | Token scope | Required | Purpose |
    |---|---|---|
    | `securityEvents.ingest` | **Yes** | Ingest security events via `/platform/ingest/v1/security.events` |
    | `metrics.ingest` | Optional | Send OTLP metrics to Dynatrace |
    | `logs.ingest` | Optional | Send OTLP logs to Dynatrace |
    | `openTelemetryTrace.ingest` | Optional | Send OTLP traces to Dynatrace |

---

## Activation and setup

### Step 1 — Create the Dynatrace API token

1. In Dynatrace, go to **Settings → Access Tokens**.
2. Select **Generate new token**.
3. Name it, e.g., `Kyverno Security Events Ingest`.
4. Select the required scopes (at minimum: **`securityEvents.ingest`**).
5. Select **Generate token** and copy the value immediately — it will not be shown again.

### Step 2 — Create the Kubernetes secret

Store your Dynatrace credentials in a Kubernetes Secret:

```bash
kubectl create secret generic dynatrace \
  --from-literal=dt_api_token=<YOUR_API_TOKEN> \
  --from-literal=dynatrace_oltp_url=https://<YOUR_ENV_ID>.live.dynatrace.com \
  --from-literal=clustername=<YOUR_CLUSTER_NAME>
```

> **Endpoint format:** Use your Dynatrace environment base URL without a trailing slash, e.g., `https://abc12345.live.dynatrace.com`. The exporter appends `/platform/ingest/v1/security.events` automatically.

### Step 3 — Deploy RBAC resources

The collector needs a ServiceAccount with read access to OpenReport CRs and Kubernetes resources.

Apply the following resources:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    app: otelcontribcol
  name: otelcontribcol
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: otelcontribcol
  labels:
    app: otelcontribcol
rules:
  - apiGroups: ["openreports.io"]
    resources: ["reports", "clusterreports"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["wgpolicyk8s.io"]
    resources: ["policyreports", "clusterpolicyreports"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events", "namespaces", "namespaces/status", "nodes",
                "nodes/spec", "pods", "pods/status", "replicationcontrollers",
                "replicationcontrollers/status", "resourcequotas", "services",
                "endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["daemonsets", "deployments", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["extensions"]
    resources: ["daemonsets", "deployments", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch"]
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]
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
    name: otelcontribcol
    namespace: default   # Adjust to your collector namespace
```

```bash
kubectl apply -f rbac.yaml
```

### Step 4 — Install Kyverno with OpenReports

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  -f kyverno-values.yaml
```

Minimum required Helm values:

```yaml
openreports:
  enabled: true
  installCrds: true

features:
  admissionReports:
    enabled: true
  aggregateReports:
    enabled: true
  policyReports:
    enabled: true
  backgroundScan:
    enabled: true
    backgroundScanInterval: 1h
```

### Step 5 — Deploy the OpenTelemetry Collector

Apply the `OpenTelemetryCollector` Custom Resource:

```yaml
apiVersion: opentelemetry.io/v1beta1
kind: OpenTelemetryCollector
metadata:
  name: otel
  labels:
    app: opentelemetry
    app.kubernetes.io/component: otel-statefullset
spec:
  mode: statefulset
  replicas: 1
  serviceAccount: otelcontribcol
  image: dynatrace-oss/dynatrace-security-events-collector:0.22
  observability:
    metrics:
      enableMetrics: true
  env:
    - name: MY_POD_IP
      valueFrom:
        fieldRef:
          apiVersion: v1
          fieldPath: status.podIP
    - name: K8S_NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
    - name: DT_ENDPOINT
      valueFrom:
        secretKeyRef:
          name: dynatrace
          key: dynatrace_oltp_url
    - name: DT_API_TOKEN
      valueFrom:
        secretKeyRef:
          name: dynatrace
          key: dt_api_token
    - name: CLUSTERNAME
      valueFrom:
        secretKeyRef:
          name: dynatrace
          key: clustername
    - name: OTEL_SERVICE_NAME
      valueFrom:
        fieldRef:
          apiVersion: v1
          fieldPath: metadata.labels['app.kubernetes.io/component']
    - name: OTEL_RESOURCE_ATTRIBUTES
      value: service.name=$(OTEL_SERVICE_NAME)
  config:
    receivers:
      k8sobjects:
        auth_type: serviceAccount
        objects:
          - name: clusterreports
            group: openreports.io
            mode: pull
            interval: 10m
          - name: reports
            group: openreports.io
            mode: pull
            interval: 10m
      otlp:
        protocols:
          grpc:
            endpoint: ${MY_POD_IP}:4317
          http:
            cors:
              allowed_origins:
                - http://*
                - https://*
            endpoint: ${MY_POD_IP}:4318
    processors:
      batch:
        send_batch_max_size: 1000
        timeout: 30s
        send_batch_size: 800
      memory_limiter:
        check_interval: 1s
        limit_percentage: 70
        spike_limit_percentage: 30
      k8sattributes/security:
        extract:
          metadata:
            - k8s.cluster.uid
        pod_association:
          - sources:
              - from: resource_attribute
                name: k8s.namespace.name
      resource:
        attributes:
          - key: k8s.cluster.name
            value: ${CLUSTERNAME}
            action: insert
      securityevent:
        processors:
          openreports:
            enabled: true
    exporters:
      securityevent:
        endpoint: "${DT_ENDPOINT}/platform/ingest/v1/security.events"
        timeout: 30s
        headers:
          Authorization: "Api-Token ${DT_API_TOKEN}"
          Content-Type: "application/json"
      otlphttp:
        endpoint: ${DT_ENDPOINT}/api/v2/otlp
        headers:
          Authorization: "Api-Token ${DT_API_TOKEN}"
      debug:
        verbosity: detailed
    service:
      pipelines:
        logs/k8sobject:
          receivers: [k8sobjects]
          processors: [memory_limiter, resource, securityevent,
                       k8sattributes/security, batch]
          exporters: [securityevent, debug]
```

```bash
kubectl apply -f otel-collector.yaml
```

### Step 6 — Verify

1. Check that OpenReports exist:

    ```bash
    kubectl get reports.openreports.io --all-namespaces
    kubectl get clusterreports.openreports.io
    ```

2. Check that the collector is running:

    ```bash
    kubectl get pods -l app=opentelemetry
    ```

3. In Dynatrace, navigate to the **Security** section and verify that new security events appear with category `COMPLIANCE`.

---

## Details

### How it works

![Architecture diagram](img/architecture.svg)

<div>
<table>
<tr><td><strong>1</strong></td><td><strong>Kyverno evaluates policies</strong></td><td>Kyverno validates, mutates, and generates Kubernetes resources. For each validating policy, Kyverno produces OpenReports containing per-resource pass/fail results with severity and compliance details.</td></tr>
<tr><td><strong>2</strong></td><td><strong>Collector pulls OpenReports</strong></td><td>The <code>k8sobjects</code> receiver in the OpenTelemetry Collector periodically pulls <code>reports</code> and <code>clusterreports</code> from the <code>openreports.io</code> API group every 10 minutes.</td></tr>
<tr><td><strong>3</strong></td><td><strong>Security Event Processor transforms data</strong></td><td>The custom <strong>securityevent</strong> processor parses each OpenReport, extracts individual policy results, and maps them to the Dynatrace security event schema — assigning severity, risk score, compliance status, and Kubernetes context.</td></tr>
<tr><td><strong>4</strong></td><td><strong>Metadata enrichment</strong></td><td>The <code>k8sattributes</code> processor adds Kubernetes metadata (cluster UID, namespace) and the <code>resource</code> processor inserts the cluster name.</td></tr>
<tr><td><strong>5</strong></td><td><strong>Security Event Exporter delivers to Dynatrace</strong></td><td>The custom <strong>securityevent</strong> exporter sends batched HTTP POST requests to <code>/platform/ingest/v1/security.events</code>, authenticated with an API token.</td></tr>
<tr><td><strong>6</strong></td><td><strong>Grail stores and indexes events</strong></td><td>Dynatrace stores the security events in Grail. They become queryable in Notebooks, Investigations, and Dashboards.</td></tr>
</table>
</div>

### Kyverno policy types that generate reports

Every policy deployed in the cluster generates a report for each targeted resource. The Security Event Processor collects those reports and sends each result status as a security event to Dynatrace.

**Policy types that produce OpenReports (and appear as security events):**

| Policy type | API group | Scope | Report type |
|---|---|---|---|
| `ClusterPolicy` | `kyverno.io/v1` | Cluster-wide | `clusterreports` |
| `Policy` | `kyverno.io/v1` | Namespaced | `reports` |
| `ClusterValidatingPolicy` | `policies.kyverno.io/v1` | Cluster-wide | `clusterreports` |
| `ValidatingPolicy` | `policies.kyverno.io/v1` | Namespaced | `reports` |
| `ImageValidatingPolicy` | `policies.kyverno.io/v1` | Cluster-wide | `clusterreports` |
| `ClusterImageValidatingPolicy` | `policies.kyverno.io/v1` | Cluster-wide | `clusterreports` |
| `NamespacedImageValidatingPolicy` | `policies.kyverno.io/v1` | Namespaced | `reports` |

**Policy types that do NOT produce reports:**

| Policy type | Reason |
|---|---|
| `MutatingPolicy` / `ClusterMutatingPolicy` | Modifies resources; no pass/fail compliance result. |
| `GeneratingPolicy` / `ClusterGeneratingPolicy` | Creates resources; no compliance check. |
| `DeletingPolicy` / `ClusterDeletingPolicy` | Cron-based cleanup; no compliance check. |
| `CleanupPolicy` / `ClusterCleanupPolicy` | Legacy cleanup; no compliance report. |

### Security event field mapping

| OpenReport field | Dynatrace security event field | Value |
|---|---|---|
| `severity: critical` | `finding.severity` / `dt.security.risk.score` | `critical` / `10.0` |
| `severity: high` | `finding.severity` / `dt.security.risk.score` | `high` / `8.9` |
| `severity: medium` | `finding.severity` / `dt.security.risk.score` | `medium` / `6.9` |
| `severity: low` | `finding.severity` / `dt.security.risk.score` | `low` / `3.9` |
| `result: pass` | `compliance.status` | `PASSED` |
| `result: fail` | `compliance.status` | `FAILED` |
| `result: error / skip` | `compliance.status` | `NOT_RELEVANT` |
| `result` (raw value) | `finding.status` | `pass`, `fail`, `error`, `skip` |
| `policy` + `rule` | `finding.title` | `policy-name - rule-name` |
| `policy` | `finding.type` / `compliance.requirements` | Policy name |
| `rule` | `compliance.control` | Rule name |
| `category` | `compliance.standards` | If present in report |
| `result.source` (e.g. `kyverno`) | `product.vendor` / `product.name` / `event.provider` | Auto-detected from report |
| `scope.uid` | `object.id` | Kubernetes resource UID |
| `scope.kind` | `object.type` | e.g. `Pod`, `Deployment` |
| `scope.name` | `object.name` | Kubernetes resource name |
| Event name | `event.name` | `Compliance finding event` (fixed) |
| Event category | `event.category` | `COMPLIANCE` (fixed) |
| Event type | `event.type` | `COMPLIANCE_FINDING` (fixed) |
| Schema version | `event.version` | `1.309` (fixed) |

### Collector configuration

For the complete collector configuration reference — including detailed documentation of the `k8sobjects` receiver, `securityevent` processor, `securityevent` exporter, and all supporting processors — see [Collector configuration](details/collector-configuration.md).

### Pipeline examples

For ready-to-use pipeline configurations covering different scenarios (minimal, production, violations-only, multi-pipeline, watch mode, multi-cluster, development), see [Pipeline examples](details/pipeline-examples.md).

### Build your own collector

To build a custom OpenTelemetry Collector with the security event plugins using OCB (OpenTelemetry Collector Builder), including adding the plugins to an existing collector, see [Build your own collector](details/build-your-own-collector.md).

---

## Monitor data

Once you ingest your Kyverno data into Grail, you can monitor the health and throughput of the pipeline using the collector's built-in metrics.

### Processor metrics (OpenTelemetry)

The Security Event Processor emits four OpenTelemetry metrics, exposed on the collector's Prometheus endpoint (port `8888`):

| Metric | Type | Description |
|---|---|---|
| `processor_securityevent_incoming_logs_total` | Counter | Total number of incoming OpenReport log records received by the processor. |
| `processor_securityevent_outgoing_logs_total` | Counter | Total output logs produced. Greater than incoming because each OpenReport expands into multiple security events (one per policy finding). |
| `processor_securityevent_dropped_logs_total` | Counter | Logs dropped due to processing errors. Should be 0 in healthy operation. |
| `processor_securityevent_processing_errors_total` | Counter | Processing failures, labeled by `error_type`. Should be 0 in healthy operation. |

### Exporter metrics (internal)

The Security Event Exporter tracks internal counters reported at shutdown and in debug logs:

| Metric | Description |
|---|---|
| `logs_received` | Total log records received by the exporter. |
| `events_exported` | Security events successfully sent to Dynatrace. |
| `events_failed` | Security events that failed to send. |
| `conversion_errors` | Log records that could not be converted to security events. |
| `http_requests` | Total HTTP requests made to the Dynatrace API. |
| `http_errors` | HTTP requests that returned non-2xx status codes. |
| `attribute_conflicts` | Cases where log attributes overwrote resource attributes (informational). |

### Accessing collector metrics

The collector exposes Prometheus metrics on port `8888`:

```bash
kubectl port-forward <collector-pod> 8888:8888
curl -s http://localhost:8888/metrics | grep processor_securityevent
```

### Key health indicators

| Indicator | What to watch | Alert condition |
|---|---|---|
| Pipeline throughput | `outgoing_logs_total` should grow steadily | No increase in 20+ minutes (reports are pulled every 10m) |
| Error rate | `processing_errors_total` and `dropped_logs_total` | Any increase above 0 |
| HTTP delivery | `events_exported` vs `events_failed` | `events_failed > 0` |
| Expansion ratio | `outgoing / incoming` | Ratio should be > 1.0 (each report contains multiple findings) |

---

## Visualize and analyze findings

You can create your own dashboards or use templates to visualize and analyze policy compliance findings.

### To use a dashboard template

1. In Dynatrace, go to **Dashboards**.
2. Create a new dashboard.
3. Add tiles using DQL queries against the `security_events` table (see [Query ingested data](#query-ingested-data)).

### Example dashboard tiles

| Tile | DQL query |
|---|---|
| Non-compliant findings by severity | `fetch security_events \| filter category == "COMPLIANCE" AND compliance.status == "FAILED" \| summarize count(), by: {severity}` |
| Compliance trend over time | `fetch security_events \| filter category == "COMPLIANCE" \| summarize count(), by: {bin(timestamp, 1h), compliance.status}` |
| Top violated policies | `fetch security_events \| filter compliance.status == "FAILED" \| summarize count(), by: {finding.title} \| sort count desc \| limit 10` |
| Findings by namespace | `fetch security_events \| filter compliance.status == "FAILED" \| summarize count(), by: {k8s.namespace.name}` |

---

## Automate and orchestrate findings

You can create your own workflows or use templates to automate and orchestrate policy compliance findings.

### To create a workflow

1. In Dynatrace, go to **Workflows**.
2. Create a new workflow.
3. Add a **Security event trigger** filtered to `category == "COMPLIANCE"`.
4. Add actions for notification, ticket creation, or remediation.

### Example workflow triggers

| Trigger | Description |
|---|---|
| Critical policy violations | `severity == "CRITICAL" AND compliance.status == "FAILED"` |
| New image verification failures | `finding.title CONTAINS "image" AND compliance.status == "FAILED"` |
| High-severity findings in production | `severity IN ("CRITICAL", "HIGH") AND k8s.namespace.name == "production"` |

---

## Query ingested data

You can query ingested data in **Notebooks** or **Investigations**, using the Grail security events data format.

### To query ingested data

1. In Dynatrace, go to **Notebooks** or **Investigations**.
2. Create a new DQL query against the `security_events` table.

### Example queries

**All Kyverno compliance events:**

```sql
fetch security_events
| filter category == "COMPLIANCE"
| sort timestamp desc
| limit 100
```

**Non-compliant findings grouped by policy:**

```sql
fetch security_events
| filter category == "COMPLIANCE" AND compliance.status == "FAILED"
| summarize count(), by: {finding.title, severity}
| sort count desc
```

**Compliance summary per namespace:**

```sql
fetch security_events
| filter category == "COMPLIANCE"
| summarize
    compliant = countIf(compliance.status == "PASSED"),
    non_compliant = countIf(compliance.status == "FAILED"),
    by: {k8s.namespace.name}
| fieldsAdd compliance_rate = compliant * 100.0 / (compliant + non_compliant)
| sort compliance_rate asc
```

**Critical violations in the last 24 hours:**

```sql
fetch security_events
| filter category == "COMPLIANCE"
    AND severity == "CRITICAL"
    AND compliance.status == "FAILED"
    AND timestamp > now() - 24h
| sort timestamp desc
```

---

## Delete connections

To stop sending events to Dynatrace:

1. Delete the OpenTelemetry Collector:

    ```bash
    kubectl delete opentelemetrycollector otel
    ```

2. Optionally, remove the RBAC resources and secret:

    ```bash
    kubectl delete clusterrolebinding otelcontribcol
    kubectl delete clusterrole otelcontribcol
    kubectl delete serviceaccount otelcontribcol
    kubectl delete secret dynatrace
    ```

This removes the Kubernetes resources created for this integration. Existing security events in Grail are retained according to your Dynatrace data retention policy.
