# Pipeline examples

This page shows various collector pipeline configurations for different scenarios. Each example is a complete `service.pipelines` section and the corresponding component configurations. Mix and match based on your requirements.

---

## Minimal — Security events only

The simplest pipeline. Pulls OpenReports, transforms them, and sends to Dynatrace. No enrichment, no debug output.

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

processors:
  securityevent:
    processors:
      openreports:
        enabled: true

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

service:
  pipelines:
    logs/security:
      receivers: [k8sobjects]
      processors: [securityevent, batch]
      exporters: [securityevent]
```

**When to use:** Development, testing, or minimal resource footprint when you don't need cluster metadata enrichment.

---

## Production — With enrichment and debug

The recommended production configuration. Adds memory protection, cluster name and UID enrichment, and a debug exporter for troubleshooting.

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

  debug:
    verbosity: detailed

service:
  pipelines:
    logs/security:
      receivers: [k8sobjects]
      processors: [memory_limiter, resource, securityevent,
                   k8sattributes/security, batch]
      exporters: [securityevent, debug]
```

**Processor ordering matters:**

1. `memory_limiter` — first, to protect against OOM
2. `resource` — adds static cluster name
3. `securityevent` — transforms OpenReports into security events
4. `k8sattributes/security` — enriches with cluster UID from API server
5. `batch` — last, to group events before sending

---

## Violations only — Filter by status

When you only want to see failures and errors in Dynatrace (skip pass and skip results). This significantly reduces event volume.

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

Combine with any pipeline example above. Only the `securityevent` processor config changes.

**When to use:** Production environments with many policies where pass results create too much noise. You can always switch to processing all statuses later.

---

## Multi-pipeline — Security events + OTLP observability

Run the security events pipeline alongside a standard OTLP pipeline for metrics, traces, and logs from other sources. Both pipelines share the same collector instance.

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
    # Pipeline 1: Security events from Kyverno
    logs/security:
      receivers: [k8sobjects]
      processors: [memory_limiter, resource, securityevent,
                   k8sattributes/security, batch]
      exporters: [securityevent, debug]

    # Pipeline 2: General OTLP metrics
    metrics/otlp:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp]

    # Pipeline 3: General OTLP traces
    traces/otlp:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp]
```

**When to use:** When you want a single collector to handle both security event ingestion and general observability data (metrics, traces) from instrumented applications in the cluster.

**Token scopes:** The API token needs `securityEvents.ingest` plus `metrics.ingest` and/or `openTelemetryTrace.ingest` depending on which OTLP pipelines you enable.

---

## Watch mode — Real-time event streaming

Instead of pulling all reports every 10 minutes, use `watch` mode to stream new and changed reports in real time. This reduces latency from policy evaluation to Dynatrace visibility.

```yaml
receivers:
  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: clusterreports
        group: openreports.io
        mode: watch
      - name: reports
        group: openreports.io
        mode: watch
```

**Trade-offs:**

- **Pros:** Lower latency (events appear in Dynatrace within seconds of report creation). No re-processing of unchanged reports.
- **Cons:** If the collector restarts, it resumes from the current state and may miss reports created during downtime. No built-in backfill.

**When to use:** When low-latency compliance visibility matters more than guaranteed delivery of historical reports.

---

## Development — Local testing without Dynatrace

For local development and testing, use only the `debug` exporter to see the transformed events in the collector logs without sending anything to Dynatrace.

```yaml
receivers:
  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: clusterreports
        group: openreports.io
        mode: pull
        interval: 1m

processors:
  securityevent:
    processors:
      openreports:
        enabled: true

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs/security:
      receivers: [k8sobjects]
      processors: [securityevent]
      exporters: [debug]
```

**What to look for in the output:**

- Each expanded security event appears as a separate log record in the debug output.
- Check `event.category`, `compliance.status`, `finding.title`, and `finding.severity` to verify the transformation is correct.
- The `processor_securityevent_outgoing_logs_total` metric should be greater than `incoming_logs_total` (one report expands into many events).

---

## Multi-cluster — Shared Dynatrace environment

When multiple clusters send security events to the same Dynatrace environment, each cluster's collector must include the cluster name as a resource attribute so events can be filtered per cluster in DQL.

```yaml
processors:
  resource:
    attributes:
      - key: k8s.cluster.name
        value: "production-eu-west-1"    # Unique per cluster
        action: insert

  k8sattributes/security:
    extract:
      metadata:
        - k8s.cluster.uid
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.namespace.name
```

In Dynatrace, filter by cluster:

```sql
fetch security_events
| filter category == "COMPLIANCE"
    AND k8s.cluster.name == "production-eu-west-1"
| sort timestamp desc
```

**Deployment tip:** Use the Kubernetes Secret or environment variable to inject the cluster name so the same collector config works across clusters:

```yaml
env:
  - name: CLUSTERNAME
    valueFrom:
      secretKeyRef:
        name: dynatrace
        key: clustername

processors:
  resource:
    attributes:
      - key: k8s.cluster.name
        value: ${CLUSTERNAME}
        action: insert
```

---

## Prometheus metrics — Filelog receiver

If you also want to collect Kyverno's own Prometheus metrics (admission latency, policy evaluation counts) alongside security events, add a `prometheus` receiver in a separate metrics pipeline.

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: kyverno
          scrape_interval: 30s
          kubernetes_sd_configs:
            - role: pod
          relabel_configs:
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
              action: keep
              regex: kyverno

service:
  pipelines:
    logs/security:
      receivers: [k8sobjects]
      processors: [memory_limiter, resource, securityevent,
                   k8sattributes/security, batch]
      exporters: [securityevent]

    metrics/kyverno:
      receivers: [prometheus]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp]
```

This requires adding the `prometheusreceiver` to the OCB manifest (already included in the default build). The API token needs the `metrics.ingest` scope.
