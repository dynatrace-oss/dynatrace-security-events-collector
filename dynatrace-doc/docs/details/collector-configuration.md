# Collector configuration

The Dynatrace Security Events Collector is a custom [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) distribution that chains three components in a logs pipeline to transform Kubernetes policy compliance data into Dynatrace security events.

---

## Pipeline data flow

The collector pipeline processes data through three stages:

```
k8sobjects receiver          securityevent processor          securityevent exporter
 (pulls OpenReports)   →    (transforms to security events)  →  (POSTs to Dynatrace)
```

Each stage is a standard OpenTelemetry Collector component configured in the `service.pipelines` section:

```yaml
service:
  pipelines:
    logs/k8sobject:
      receivers: [k8sobjects]
      processors: [memory_limiter, resource, securityevent, k8sattributes/security, batch]
      exporters: [securityevent, debug]
```

The pipeline type is `logs` because the `k8sobjects` receiver emits Kubernetes objects as log records. The processor and exporter operate on these log records.

---

## Stage 1 — k8sobjects receiver

The [`k8sobjects` receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver) is an upstream OpenTelemetry Collector Contrib component that watches or pulls Kubernetes Custom Resources and emits them as log records.

In this pipeline, it pulls OpenReports — the standardized compliance report format from Kyverno (and other policy engines that implement the [OpenReports](https://github.com/kyverno/reports-server) specification).

### Configuration

```yaml
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
```

| Parameter | Description |
|---|---|
| `auth_type` | Authentication method. Use `serviceAccount` when running inside Kubernetes. |
| `objects[].name` | The Kubernetes resource name to watch. `clusterreports` for cluster-scoped, `reports` for namespaced. |
| `objects[].group` | The API group. OpenReports use `openreports.io`. |
| `objects[].mode` | `pull` fetches all objects on a schedule. `watch` streams changes in real time. |
| `objects[].interval` | How often to pull. Default: `10m`. Lower values increase API server load. |

### What the receiver outputs

Each pulled OpenReport becomes a log record where the body is a Map containing the full CRD object. The processor identifies OpenReports by checking for `kind: Report` and `apiVersion: openreports.io/v1alpha1` in the body (or attributes).

A single OpenReport typically contains many individual policy results — one per resource evaluated. For example, if a policy targets 50 Deployments, the report contains 50 results.

### Considerations

- **Pull vs Watch:** `pull` mode fetches all reports every interval, which means the processor re-processes them and relies on deduplication (SHA256 hash) to avoid sending duplicate events. `watch` mode only sees new or changed reports, reducing load but potentially missing reports if the collector restarts.

- **Interval tuning:** Kyverno's background scanner runs every 1 hour by default. Setting `interval: 10m` ensures reports are picked up shortly after generation. Setting a very low interval (e.g., `1m`) adds unnecessary API server load.

- **RBAC:** The service account must have `get`, `list`, `watch` permissions on `reports` and `clusterreports` in the `openreports.io` API group. See the RBAC section in the [activation and setup](#) guide.

---

## Stage 2 — securityevent processor

The `securityevent` processor is a custom component that parses OpenReport log records and transforms each policy result into a structured Dynatrace security event.

### What it does

1. **Identifies OpenReports** — Checks each incoming log record for `kind: Report` and `apiVersion: openreports.io/v1alpha1`. Non-matching logs pass through unchanged.

2. **Extracts results** — Parses the report's `results` array. Each result represents one policy evaluation against one Kubernetes resource.

3. **Expands to individual events** — One report with 50 results becomes 50 individual security event log records.

4. **Maps to Dynatrace schema** — Sets severity, compliance status, risk score, finding title, product vendor, Kubernetes context, and all required security event fields.

5. **Deduplicates** — Uses SHA256 hashing per pod to avoid emitting duplicate events when the same report is pulled multiple times.

### Configuration

```yaml
processors:
  securityevent:
    processors:
      openreports:
        enabled: true
```

| Parameter | Default | Description |
|---|---|---|
| `processors.openreports.enabled` | `false` | Enable the OpenReports transformation. Must be set to `true`. |
| `processors.openreports.status_filter` | *(all statuses)* | Optional list to limit which result statuses are processed. |

### Filtering by status

By default, all result statuses are processed: `pass`, `fail`, `error`, `skip`. To process only specific statuses:

```yaml
processors:
  securityevent:
    processors:
      openreports:
        enabled: true
        status_filter:
          - "fail"
          - "error"
```

This is useful when you only care about violations and errors, reducing event volume and Dynatrace ingest cost.

### Severity mapping

The processor maps the Kyverno policy severity to the Dynatrace security event severity and a numeric risk score:

| OpenReport severity | Dynatrace severity | `dt.security.risk.score` | OTel SeverityNumber |
|---|---|---|---|
| `critical` | `CRITICAL` | `10.0` | FATAL |
| `high` | `HIGH` | `8.9` | ERROR |
| `medium` (default) | `MEDIUM` | `6.9` | WARN |
| `low` | `LOW` | `3.9` | INFO |
| *(missing/unknown)* | `MEDIUM` | `0.0` | WARN |

### Compliance status mapping

| OpenReport result | `compliance.status` |
|---|---|
| `pass` | `PASSED` |
| `fail` | `FAILED` |
| `error` | `NOT_RELEVANT` |
| `skip` | `NOT_RELEVANT` |

### Event description

The processor generates a human-readable description that varies by result status:

| Result | `event.description` |
|---|---|
| `fail` | `Policy violation on {resource} for rule {rule}` |
| `pass` | `Policy check passed on {resource} for rule {rule}` |
| `error` | `Policy check error on {resource} for rule {rule}` |
| `skip` | `Policy check skipped on {resource} for rule {rule}` |
| *(other)* | `Policy evaluation on {resource} for rule {rule}` |

### Complete attribute reference

Every security event produced by the processor includes the following attributes:

**Event metadata**

| Attribute | Source | Description |
|---|---|---|
| `event.id` | Generated UUID | Unique per event |
| `event.version` | Fixed: `1.309` | Security event schema version |
| `event.category` | Fixed: `COMPLIANCE` | Event category |
| `event.type` | Fixed: `COMPLIANCE_FINDING` | Event type |
| `event.name` | Fixed: `Compliance finding event` | Event name |
| `event.description` | Computed | Varies by result status (see table above) |
| `event.provider` | `result.source` | Auto-detected from report (e.g., `kyverno`) |
| `event.original_content` | Enriched JSON | Result JSON merged with Kubernetes metadata |

**Product fields**

| Attribute | Source | Description |
|---|---|---|
| `product.vendor` | `result.source` | Auto-detected (e.g., `kyverno`) |
| `product.name` | `result.source` | Same value as `product.vendor` |

**Finding fields**

| Attribute | Source | Description |
|---|---|---|
| `finding.id` | Generated UUID | Unique per finding |
| `finding.title` | `policy` + `rule` | Combined as `policy - rule` (dash-separated) |
| `finding.type` | `result.policy` | The policy name |
| `finding.severity` | `result.severity` | Original value from report (lowercase) |
| `finding.status` | `result.result` | Raw status: `pass`, `fail`, `error`, `skip` |
| `finding.time.created` | `result.timestamp` | RFC3339Nano format |
| `finding.url` | `result.properties.url` | Only if present in report |

**Compliance fields**

| Attribute | Source | Description |
|---|---|---|
| `compliance.status` | `result.result` | Normalized: `PASSED`, `FAILED`, `NOT_RELEVANT` |
| `compliance.control` | `result.rule` | The rule name |
| `compliance.requirements` | `result.policy` | The policy name |
| `compliance.standards` | `result.category` | Only if present in report |

**Risk score**

| Attribute | Source | Description |
|---|---|---|
| `dt.security.risk.score` | `result.severity` | Numeric: `10.0`, `8.9`, `6.9`, `3.9`, or `0.0` |

**Object fields**

| Attribute | Source | Description |
|---|---|---|
| `object.id` | `scope.uid` | Kubernetes resource UID |
| `object.type` | `scope.kind` | e.g., `Pod`, `Deployment` |
| `object.name` | `scope.name` | Kubernetes resource name |
| `smartscape.type` | `scope.kind` | `K8S_POD` when scope is a Pod |

**Kubernetes context**

| Attribute | Source | Description |
|---|---|---|
| `k8s.namespace.name` | `scope.namespace` | Always set |
| `k8s.pod.name` | `scope.name` | Only when `scope.kind` is `Pod` |
| `k8s.pod.uid` | `scope.uid` | Only when `scope.kind` is `Pod` |
| `k8s.deployment.name` | Owner reference | Inferred from owner refs or pod name pattern |
| `k8s.statefulset.name` | Owner reference | When workload is a StatefulSet |
| `k8s.daemonset.name` | Owner reference | When workload is a DaemonSet |
| `k8s.workload.name` | Owner reference | Workload name regardless of kind |
| `k8s.workload.kind` | Owner reference | Defaults to `Deployment` if inferred from pod name |
| `k8s.workload.uid` | Owner reference | Workload resource UID |
| `k8s.cluster.uid` | Downstream | Added by `k8sattributes/security` processor |
| `k8s.cluster.name` | Downstream | Added by `resource` processor |

### Processor metrics

The processor emits four OpenTelemetry metrics, exposed on the collector's Prometheus endpoint (port `8888`):

| Metric | Type | Description |
|---|---|---|
| `processor_securityevent_incoming_logs_total` | Counter | Total incoming log records. |
| `processor_securityevent_outgoing_logs_total` | Counter | Total output logs. Greater than incoming because each report expands into multiple events. |
| `processor_securityevent_dropped_logs_total` | Counter | Logs dropped due to processing errors. Should be 0. |
| `processor_securityevent_processing_errors_total` | Counter | Processing failures, labeled by `error_type`. Should be 0. |

### Stability

The processor component stability is **Development**. The attribute schema may evolve in future versions.

---

## Stage 3 — securityevent exporter

The `securityevent` exporter is a custom component that converts the processed log records into flat JSON objects and POSTs them in batches to the Dynatrace Security Events Ingest API.

### What it does

1. **Flattens log records** — Converts each OTel log record to a flat JSON object: resource attributes first, then log attributes (overwriting on conflict), plus a `timestamp` field.

2. **Adds default attributes** — Merges `default_attributes` from the config into every event. Note: the `source` key is filtered out even if configured.

3. **Batches events** — Collects all events from a single `ConsumeLogs` call into a JSON array and sends one HTTP POST.

4. **Authenticates** — Headers (including the API token) are sent with every request. Token values use `configopaque` for secure handling in logs and config dumps.

### Configuration

```yaml
exporters:
  securityevent:
    endpoint: "${DT_ENDPOINT}/platform/ingest/v1/security.events"
    timeout: 30s
    headers:
      Authorization: "Api-Token ${DT_API_TOKEN}"
      Content-Type: "application/json"
```

| Parameter | Default | Description |
|---|---|---|
| `endpoint` | *(required)* | Full URL to the Dynatrace Security Events Ingest API. |
| `timeout` | `30s` | HTTP request timeout. |
| `headers` | *(required)* | HTTP headers. Must include `Authorization` with an API token that has `securityEvents.ingest` scope. |
| `default_attributes` | `{"source": "opentelemetry-collector"}` | Key-value pairs added to every event. The `source` key is filtered out. |

### Retry and queue (not yet wired up)

The exporter accepts `retry_on_failure` and `sending_queue` in the configuration, but the current implementation does **not** use the OTel `exporterhelper` retry/queue wrappers. The exporter performs a single HTTP POST per batch. If the request fails, the error is returned to the collector pipeline. Retry and queue support is planned for a future version.

### Exporter metrics

The exporter tracks internal counters reported in debug logs and at shutdown:

| Counter | Description |
|---|---|
| `logs_received` | Total log records received by the exporter. |
| `events_exported` | Security events successfully sent to Dynatrace. |
| `events_failed` | Security events that failed to send. |
| `conversion_errors` | Log records that could not be converted to security events. |
| `http_requests` | Total HTTP requests made to the Dynatrace API. |
| `http_errors` | HTTP requests that returned non-2xx status codes. |
| `attribute_conflicts` | Cases where log attributes overwrote resource attributes (informational). |

### Stability

The exporter component stability is **Stable**.

---

## Supporting processors

The pipeline typically includes additional standard OTel processors between the receiver and exporter for resource management and batching.

### memory_limiter

Protects the collector from running out of memory:

```yaml
processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 70
    spike_limit_percentage: 30
```

Should be placed **first** in the processor chain to reject data before processing when memory is constrained.

### resource

Inserts static resource attributes like the cluster name:

```yaml
processors:
  resource:
    attributes:
      - key: k8s.cluster.name
        value: ${CLUSTERNAME}
        action: insert
```

### k8sattributes

Enriches log records with Kubernetes metadata from the API server:

```yaml
processors:
  k8sattributes/security:
    extract:
      metadata:
        - k8s.cluster.uid
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.namespace.name
```

This adds `k8s.cluster.uid` to every security event, enabling correlation across clusters in Dynatrace.

### batch

Groups log records into batches before sending, reducing the number of HTTP requests:

```yaml
processors:
  batch:
    send_batch_max_size: 1000
    timeout: 30s
    send_batch_size: 800
```

Should be placed **last** in the processor chain (just before the exporters).

---

## Complete configuration reference

Here is the full collector configuration used in the default deployment:

```yaml
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
        endpoint: ${MY_POD_IP}:4318

processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 70
    spike_limit_percentage: 30

  resource:
    attributes:
      - key: k8s.cluster.name
        value: ${CLUSTERNAME}
        action: insert

  securityevent:
    processors:
      openreports:
        enabled: true

  k8sattributes/security:
    extract:
      metadata:
        - k8s.cluster.uid
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.namespace.name

  batch:
    send_batch_max_size: 1000
    timeout: 30s
    send_batch_size: 800

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
