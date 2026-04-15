# Visualize and analyze findings

Create dashboards and analyze Kyverno policy compliance data in Dynatrace.

---

## Kyverno — Security & Health dashboard

A pre-built dashboard is included in this repository at [`dynatrace/kyverno-security-health-dashboard.json`](https://github.com/dynatrace-oss/dynatrace-security-events-collector/blob/main/dynatrace/kyverno-security-health-dashboard.json).

### Dashboard sections

The dashboard is organized into two sections:

**Security overview (top):**

- Validation Policies Status — color-coded ready/not-ready table
- Policy Failure per Namespace — pie chart
- Failed Policy Results by Namespace — honeycomb visualization
- Policy Results Over Time — line chart by policy and result
- Compliance Findings — `fetch security.events | filter event.type == "COMPLIANCE_FINDING"`
- Security Event Processor — `processor_securityevent_incoming_logs_total` and `processor_securityevent_outgoing_logs_total` line charts

**Health overview (bottom):**

- Policy Reports Detail — full report table with error/fail/warn coloring
- Admission Controller — execution and review duration
- Kyverno Error Logs — parsed JSON logs filtered for errors
- Controllers — queue depth, reconcile, events dropped
- Resource Usage — CPU and memory by deployment

### Import the dashboard

Use [dtctl](https://github.com/dynatrace-oss/dtctl) to apply the dashboard to your environment:

```bash
dtctl apply -f dynatrace/kyverno-security-health-dashboard.json
```

Or import manually:

1. In Dynatrace, go to **Dashboards**.
2. Select **Upload**.
3. Select the `dynatrace/kyverno-security-health-dashboard.json` file.

---

## Custom dashboard tiles

You can create your own dashboard tiles using DQL queries against the `security_events` table.

### Non-compliant findings by severity

```sql
fetch security_events
| filter event.category == "COMPLIANCE"
    AND compliance.status == "FAILED"
| summarize count(), by: {finding.severity}
```

**Visualization:** Pie chart or bar chart.

### Compliance trend over time

```sql
fetch security_events
| filter event.category == "COMPLIANCE"
| summarize count(), by: {bin(timestamp, 1h), compliance.status}
```

**Visualization:** Line chart (stacked area).

### Top violated policies

```sql
fetch security_events
| filter compliance.status == "FAILED"
| summarize count(), by: {finding.title}
| sort count desc
| limit 10
```

**Visualization:** Horizontal bar chart.

### Findings by namespace

```sql
fetch security_events
| filter compliance.status == "FAILED"
| summarize count(), by: {k8s.namespace.name}
```

**Visualization:** Pie chart or table.

### Compliance rate per namespace

```sql
fetch security_events
| filter event.category == "COMPLIANCE"
| summarize
    passed = countIf(compliance.status == "PASSED"),
    failed = countIf(compliance.status == "FAILED"),
    by: {k8s.namespace.name}
| fieldsAdd compliance_rate = passed * 100.0 / (passed + failed)
| sort compliance_rate asc
```

**Visualization:** Table with conditional formatting.

---

## Investigation workflows

### Investigating a policy violation

1. In the dashboard, identify the failing policy from the **Top violated policies** tile.
2. Click through to see which resources are affected.
3. Use DQL to drill down:

    ```sql
    fetch security_events
    | filter finding.title CONTAINS "<policy-name>"
        AND compliance.status == "FAILED"
    | fields timestamp, object.name, object.type, k8s.namespace.name, finding.title
    | sort timestamp desc
    ```

4. Correlate with Kubernetes events and logs in the same Notebook.

### Cross-cluster comparison

If you ingest data from multiple clusters, compare compliance posture:

```sql
fetch security_events
| filter event.category == "COMPLIANCE"
| summarize
    passed = countIf(compliance.status == "PASSED"),
    failed = countIf(compliance.status == "FAILED"),
    by: {k8s.cluster.name}
| fieldsAdd compliance_rate = passed * 100.0 / (passed + failed)
| sort compliance_rate asc
```

---

## Dashboard best practices

- **Refresh interval:** Set tiles to auto-refresh every 5–10 minutes to match the collector pull interval.
- **Time range:** Default to 24 hours for operational dashboards, 7 days for trend analysis.
- **Filters:** Add dashboard variables for `k8s.cluster.name` and `k8s.namespace.name` to enable interactive filtering.
- **Alerts:** Pair dashboard tiles with Dynatrace workflows for automated alerting on critical violations. See [Monitor data](monitor-data.md) for alerting strategies.
