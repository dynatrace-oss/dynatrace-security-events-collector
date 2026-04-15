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
    * Deploy at least one validating policy. See [Kyverno policy types that generate reports](details/how-it-works.md#kyverno-policy-types-that-generate-reports).

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
