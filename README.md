# Dynatrace Security Events Collector

[![Release](https://img.shields.io/github/v/release/dynatrace-oss/dynatrace-security-events-collector?style=flat-square)](https://github.com/dynatrace-oss/dynatrace-security-events-collector/releases/latest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/dynatrace-oss/dynatrace-security-events-collector/build-and-release.yml?branch=main&style=flat-square)](https://github.com/dynatrace-oss/dynatrace-security-events-collector/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/dynatrace-oss/dynatrace-security-events-collector?style=flat-square)](https://goreportcard.com/report/github.com/dynatrace-oss/dynatrace-security-events-collector)
[![License](https://img.shields.io/github/license/dynatrace-oss/dynatrace-security-events-collector?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-blue?style=flat-square)](https://go.dev/)
[![OTel Collector](https://img.shields.io/badge/otel--collector-v0.150.0-blueviolet?style=flat-square)](https://opentelemetry.io/docs/collector/)

An [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) distribution that transforms Kubernetes policy compliance data into [Dynatrace Security Events](https://docs.dynatrace.com/docs/shortlink/security-events-api). It bridges the gap between Kubernetes policy engines like [Kyverno](https://kyverno.io/) and Dynatrace's security posture management, giving you real-time compliance visibility without custom integration code.

## Why This Exists

Kubernetes policy engines evaluate workloads against security and compliance rules, but the results stay locked inside the cluster as CRD objects. Dynatrace has a Security Events API that can ingest structured findings for centralized visibility, alerting, and dashboarding — but nothing connects the two out of the box.

This collector solves that. It watches for [OpenReports](https://github.com/kyverno/reports-server) (the standardized report format from Kyverno), transforms each policy result into a Dynatrace-compatible security event with proper severity, compliance status, and Kubernetes context, then ships it to the Dynatrace Security Events API.

The result: every policy pass, fail, error, or skip across your clusters shows up in Dynatrace as a structured security finding — no custom scripts, no polling loops, no manual mapping.

## How It Works

The collector includes two custom OTel plugins that form a pipeline:

```
Kubernetes (OpenReports CRDs)
    │
    ▼
┌──────────────────────────┐
│  k8sobjects receiver     │  Watches for Report/ClusterReport CRDs
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  securityevent processor │  Parses OpenReports, extracts policy results,
│                          │  maps severity/compliance, adds K8s context
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  securityevent exporter  │  Batches and POSTs to Dynatrace
│                          │  /platform/ingest/v1/security.events
└──────────────────────────┘
```

**Security Event Processor** — Transforms each OpenReports policy result into a structured security event. One report with 50 policy results becomes 50 individual security events, each with severity mapping (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`), compliance status (`PASSED`/`FAILED`/`NOT_RELEVANT`), risk scoring, and full Kubernetes object context (namespace, workload type, pod name).

**Security Event Exporter** — Converts OTel log records to flat JSON and sends them to the Dynatrace Security Events API in configurable batches with authentication via API token.

## Quick Start

### Prerequisites

- A Kubernetes cluster with [Kyverno](https://kyverno.io/) installed and policies active
- Kyverno [Reports Server](https://github.com/kyverno/reports-server) generating OpenReports
- A Dynatrace environment with a [Security Events API token](https://docs.dynatrace.com/docs/shortlink/security-events-api) (`securityEvents.ingest` scope)

### Deploy with Docker

```bash
docker pull ghcr.io/dynatrace-oss/dynatrace-security-events-collector:latest

docker run -e DT_ENDPOINT="https://your-environment.dynatrace.com" \
           -e DT_API_TOKEN="dt0c01.xxx" \
           ghcr.io/dynatrace-oss/dynatrace-security-events-collector:latest
```

### Deploy to Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-events-collector
  namespace: dynatrace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-events-collector
  template:
    metadata:
      labels:
        app: security-events-collector
    spec:
      serviceAccountName: security-events-collector
      containers:
        - name: collector
          image: ghcr.io/dynatrace-oss/dynatrace-security-events-collector:latest
          env:
            - name: DT_ENDPOINT
              valueFrom:
                secretKeyRef:
                  name: dynatrace-secrets
                  key: endpoint
            - name: DT_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: dynatrace-secrets
                  key: api-token
          ports:
            - containerPort: 4317  # OTLP gRPC
            - containerPort: 4318  # OTLP HTTP
            - containerPort: 8888  # Prometheus metrics
```

See the [full documentation](dynatrace-doc/get-started/overview.md) for RBAC setup, configuration options, and collector pipeline details.

## Building from Source

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Build Docker image
make docker

# Run tests
make test

# Run all quality checks
make lint && make vet && make vulncheck
```

## Repository Structure

```
.
├── .github/workflows/     CI/CD pipeline (lint, test, build, release)
├── src/
│   ├── SecurityLogEventProcessor/   Processor plugin (Go module)
│   └── SecurityEventExporter/       Exporter plugin (Go module)
├── ocb/
│   ├── manifest.yaml      OCB build manifest (components + versions)
│   ├── config.yaml        Default collector configuration
│   └── build.sh           Local build helper script
├── docker/
│   └── Dockerfile         Multi-stage production image
├── dynatrace-doc/         Documentation (source of truth)
├── Makefile               Build targets (build, test, lint, docker)
└── README.md
```

## Documentation

The full documentation covers configuration, RBAC, policy types, field mappings, deployment, and troubleshooting:

- **[Getting Started](dynatrace-doc/get-started/overview.md)** — Prerequisites, API token setup, deployment
- **[How It Works](dynatrace-doc/details/how-it-works.md)** — Architecture, field mapping, compliance status
- **[Collector Configuration](dynatrace-doc/details/collector-configuration.md)** — Complete attribute reference, receiver, processor, exporter
- **[Pipeline Examples](dynatrace-doc/details/pipeline-examples.md)** — Production, minimal, multi-pipeline, watch mode, dev
- **[Build Your Own Collector](dynatrace-doc/details/build-your-own-collector.md)** — OCB manifest, custom builds, Docker

## Components

| Component | Type | Stability | Description |
|-----------|------|-----------|-------------|
| `securityevent` processor | Processor | Development | Transforms OpenReports into Dynatrace security events |
| `securityevent` exporter | Exporter | Stable | HTTP POST to Dynatrace Security Events API |
| `k8sobjects` receiver | Receiver | Beta | Watches Kubernetes CRDs (upstream contrib) |
| `otlp` receiver | Receiver | Stable | Standard OTLP ingestion (upstream core) |

Built on OpenTelemetry Collector **v0.150.0** using [OCB](https://opentelemetry.io/docs/collector/custom-collector/) (OpenTelemetry Collector Builder).

## Contributing

Contributions are welcome. Please open an issue first to discuss significant changes.

```bash
# Clone and set up
git clone https://github.com/dynatrace-oss/dynatrace-security-events-collector.git
cd dynatrace-security-events-collector

# Run quality checks
make test
make lint

# Build locally
make build
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
