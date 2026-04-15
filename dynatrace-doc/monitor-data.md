# Monitor data

Monitor the health and throughput of the Dynatrace Security Events Collector pipeline.

---

## Processor metrics

The Security Event Processor emits OpenTelemetry metrics on the collector's Prometheus endpoint (port `8888`):

| Metric | Type | Description |
|---|---|---|
| `processor_securityevent_incoming_logs_total` | Counter | Total incoming OpenReport log records received. |
| `processor_securityevent_outgoing_logs_total` | Counter | Total output logs produced. Greater than incoming because each OpenReport expands into multiple security events. |
| `processor_securityevent_dropped_logs_total` | Counter | Logs dropped due to processing errors. Should be 0 in healthy operation. |
| `processor_securityevent_processing_errors_total` | Counter | Processing failures, labeled by `error_type`. Should be 0. |

## Exporter metrics

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

---

## Accessing collector metrics

```bash
kubectl port-forward <collector-pod> 8888:8888
curl -s http://localhost:8888/metrics | grep processor_securityevent
```

---

## Kubernetes pod health checks

**Check collector pod status:**

```bash
kubectl get pods -l app=opentelemetry
```

**Check pod events for errors:**

```bash
kubectl describe pod -l app=opentelemetry | grep -A10 Events
```

**Check pod resource usage:**

```bash
kubectl top pod -l app=opentelemetry
```

---

## DQL-based monitoring

Use these queries in Dynatrace **Notebooks** to monitor the pipeline from within the platform:

**Event ingestion rate (last 24h, hourly):**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND timestamp > now() - 24h
| summarize count(), by: {bin(timestamp, 1h)}
```

**Events by cluster:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND timestamp > now() - 1h
| summarize count(), by: {k8s.cluster.name}
```

**Detect gaps in event delivery:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| summarize last_event = max(timestamp)
| fieldsAdd gap_minutes = (now() - last_event) / 60000000000
```

If `gap_minutes` exceeds 20 (two pull intervals), investigate the collector.

---

## Alerting strategies

### Prometheus-based alerts

If you scrape the collector's metrics endpoint, create alerts for:

| Alert | Condition | Severity |
|---|---|---|
| Processing errors | `processor_securityevent_processing_errors_total > 0` | Warning |
| Dropped logs | `processor_securityevent_dropped_logs_total > 0` | Warning |
| No throughput | No increase in `outgoing_logs_total` for 20+ minutes | Critical |
| Export failures | `events_failed > 0` | Warning |

### DQL-based alerts in Dynatrace

Create a Dynatrace workflow with a timer trigger to check event flow:

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| summarize last_event = max(timestamp)
| fieldsAdd gap = now() - last_event
| filter gap > duration("30m")
```

---

## Health check summary

| Indicator | Healthy state | Alert condition |
|---|---|---|
| Pipeline throughput | `outgoing_logs_total` grows steadily | No increase in 20+ minutes |
| Error rate | `processing_errors_total` = 0, `dropped_logs_total` = 0 | Any increase above 0 |
| HTTP delivery | `events_exported` > 0, `events_failed` = 0 | `events_failed > 0` |
| Expansion ratio | `outgoing / incoming` > 1.0 | Ratio = 0 or ratio = 1.0 (single finding per report is unusual) |
| Pod status | `Running`, no restarts | `CrashLoopBackOff`, restarts > 0 |
