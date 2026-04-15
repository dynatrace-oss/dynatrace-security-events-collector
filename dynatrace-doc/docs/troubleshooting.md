# Troubleshooting

Common issues and diagnostic steps for the Dynatrace Security Events Collector.

---

## Collector pod not starting

**Symptoms:** Pod in `CrashLoopBackOff` or `Error` state.

**Steps:**

1. Check pod logs:

    ```bash
    kubectl logs -l app=opentelemetry --tail=100
    ```

2. Verify the ServiceAccount and RBAC resources exist:

    ```bash
    kubectl get serviceaccount otelcontribcol
    kubectl get clusterrole otelcontribcol
    kubectl get clusterrolebinding otelcontribcol
    ```

3. Verify the Kubernetes secret has all required keys:

    ```bash
    kubectl get secret dynatrace -o jsonpath='{.data}' | jq 'keys'
    ```

    Expected keys: `dt_api_token`, `dynatrace_oltp_url`, `clustername`.

---

## No security events in Dynatrace

**Symptoms:** Collector is running but no events appear in the Security section.

**Steps:**

1. Verify OpenReports exist in the cluster:

    ```bash
    kubectl get reports.openreports.io --all-namespaces
    kubectl get clusterreports.openreports.io
    ```

    If no reports exist, check that Kyverno is installed with OpenReports enabled (`openreports.enabled: true`).

2. Check processor metrics for activity:

    ```bash
    kubectl port-forward <collector-pod> 8888:8888
    curl -s http://localhost:8888/metrics | grep processor_securityevent
    ```

    - `processor_securityevent_incoming_logs_total` should be > 0.
    - If 0, the receiver is not pulling reports — check RBAC permissions.

3. Check for processing errors:

    ```bash
    curl -s http://localhost:8888/metrics | grep -E "dropped_logs|processing_errors"
    ```

    Both should be 0. If not, enable debug logging (see below).

4. Verify the exporter endpoint and token:

    ```bash
    kubectl get secret dynatrace -o jsonpath='{.data.dynatrace_oltp_url}' | base64 -d
    ```

    The URL should be your Dynatrace environment base URL without a trailing slash.

---

## Exporter delivery failures

**Symptoms:** `events_failed` or `http_errors` counters are non-zero, or debug logs show HTTP 4xx/5xx responses.

**Steps:**

1. Check the API token has the `securityEvents.ingest` scope in **Settings > Access Tokens**.

2. Verify the endpoint URL format is correct:

    ```
    https://<YOUR_ENV_ID>.live.dynatrace.com
    ```

    The exporter appends `/platform/ingest/v1/security.events` automatically — do not include it in the URL.

3. Test connectivity from the pod:

    ```bash
    kubectl exec <collector-pod> -- wget -q -O- --header="Authorization: Api-Token $(kubectl get secret dynatrace -o jsonpath='{.data.dt_api_token}' | base64 -d)" "$(kubectl get secret dynatrace -o jsonpath='{.data.dynatrace_oltp_url}' | base64 -d)/platform/ingest/v1/security.events" 2>&1 | head -5
    ```

---

## RBAC permission errors

**Symptoms:** Logs show `Forbidden` or `cannot list resource` errors.

**Steps:**

1. Verify the ClusterRole includes the `openreports.io` API group:

    ```bash
    kubectl get clusterrole otelcontribcol -o yaml | grep -A5 openreports
    ```

2. Verify the ClusterRoleBinding references the correct ServiceAccount and namespace:

    ```bash
    kubectl get clusterrolebinding otelcontribcol -o yaml
    ```

3. Test access manually:

    ```bash
    kubectl auth can-i list reports.openreports.io --as=system:serviceaccount:default:otelcontribcol --all-namespaces
    ```

---

## Enable debug logging

To get detailed pipeline output, set the `debug` exporter verbosity to `detailed` in your collector config:

```yaml
exporters:
  debug:
    verbosity: detailed
```

Then check the logs:

```bash
kubectl logs -l app=opentelemetry --tail=200 | grep -i "security\|error\|debug"
```

---

## DQL verification queries

Use these queries in Dynatrace **Notebooks** to verify events are arriving:

**Check recent events:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
| sort timestamp desc
| limit 10
```

**Check event count over the last hour:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND timestamp > now() - 1h
| summarize count()
```

**Check for specific cluster:**

```sql
fetch security_events
| filter event.type == "COMPLIANCE_FINDING"
    AND k8s.cluster.name == "<YOUR_CLUSTER_NAME>"
| summarize count(), by: {compliance.status}
```
