# Query ingested data

Query Kyverno policy compliance findings and security events in Dynatrace using DQL (Dynatrace Query Language).

---

## Getting started

1. In Dynatrace, go to **Notebooks** or **Investigations**.
2. Create a new DQL query against the `security_events` table.

All Kyverno security events have `event.type == "COMPLIANCE_FINDING"` and `event.category == "COMPLIANCE"`.

---

## Filter by compliance status

**All Kyverno compliance events:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| sort timestamp desc
| limit 100
```

**Non-compliant findings only:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "FAILED"
| sort timestamp desc
```

**Passed findings only:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "PASSED"
| sort timestamp desc
```

---

## Filter by severity

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND finding.severity == "CRITICAL"
    AND compliance.status == "FAILED"
| sort timestamp desc
```

Replace `"CRITICAL"` with `"HIGH"`, `"MEDIUM"`, or `"LOW"` as needed.

---

## Filter by namespace

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND k8s.namespace.name == "production"
| sort timestamp desc
```

---

## Filter by policy

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND finding.title CONTAINS "require-labels"
| sort timestamp desc
```

---

## Filter by time

**Last 24 hours:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND timestamp > now() - 24h
| sort timestamp desc
```

**Specific time range:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND timestamp >= toTimestamp("2026-04-01T00:00:00Z")
    AND timestamp < toTimestamp("2026-04-15T00:00:00Z")
| sort timestamp desc
```

---

## Aggregation queries

### Violations per namespace

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "FAILED"
| summarize violations = count(), by: {k8s.namespace.name}
| sort violations desc
```

### Compliance ratio per namespace

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| summarize
    compliant = countIf(compliance.status == "PASSED"),
    non_compliant = countIf(compliance.status == "FAILED"),
    by: {k8s.namespace.name}
| fieldsAdd compliance_rate = compliant * 100.0 / (compliant + non_compliant)
| sort compliance_rate asc
```

### Top violated policies

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "FAILED"
| summarize violations = count(), by: {finding.title}
| sort violations desc
| limit 10
```

### Top violated resources

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "FAILED"
| summarize violations = count(), by: {object.name, object.type, k8s.namespace.name}
| sort violations desc
| limit 20
```

### Non-compliant findings grouped by severity

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND compliance.status == "FAILED"
| summarize count(), by: {finding.severity}
```

### Compliance trend over time

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| summarize count(), by: {bin(timestamp, 1h), compliance.status}
```

---

## Field reference

| Field | Description | Example values |
|---|---|---|
| `event.type` | Event type | `COMPLIANCE_FINDING` |
| `event.category` | Event category | `COMPLIANCE` |
| `event.name` | Event name | `Compliance finding event` |
| `compliance.status` | Compliance result | `PASSED`, `FAILED`, `NOT_RELEVANT` |
| `compliance.control` | Rule name | `require-labels` |
| `compliance.requirements` | Policy name | `require-labels-policy` |
| `finding.title` | Policy + rule | `require-labels-policy - require-labels` |
| `finding.severity` | Severity level | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `finding.status` | Raw result | `pass`, `fail`, `error`, `skip` |
| `dt.security.risk.score` | Numeric risk score | `10.0`, `8.9`, `6.9`, `3.9` |
| `object.id` | Kubernetes resource UID | UUID string |
| `object.type` | Resource kind | `Pod`, `Deployment` |
| `object.name` | Resource name | `my-app-pod-xyz` |
| `k8s.namespace.name` | Namespace | `default`, `production` |
| `k8s.cluster.name` | Cluster name | From secret configuration |
| `k8s.cluster.uid` | Cluster UID | UUID string |
| `product.vendor` | Source tool | `kyverno` |
| `product.name` | Source tool | `kyverno` |
