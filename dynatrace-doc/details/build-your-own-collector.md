# Build your own collector

The Dynatrace Security Events Collector is built using [OCB (OpenTelemetry Collector Builder)](https://opentelemetry.io/docs/collector/custom-collector/), the official tool for creating custom OpenTelemetry Collector distributions. You can use OCB to build a collector that includes exactly the components you need — including the security event plugins from this project.

---

## What is OCB?

OCB is a Go command-line tool that generates a custom OpenTelemetry Collector binary from a YAML manifest. The manifest declares which receivers, processors, exporters, and extensions to include. OCB resolves the Go module dependencies, generates the wiring code, and compiles the binary.

This means you can:

- Include only the components you need (smaller binary, reduced attack surface)
- Add the security event plugins alongside any other OTel components
- Pin specific component versions for reproducible builds
- Use Go module `replaces` for local development with monorepo source code

---

## Prerequisites

- **Go 1.24+** installed
- **OCB** installed (the build process installs it automatically via `make install-ocb`)

To install OCB manually:

```bash
go install go.opentelemetry.io/collector/cmd/builder@v0.150.0
mv $(go env GOPATH)/bin/builder $(go env GOPATH)/bin/ocb
```

---

## The manifest file

The OCB manifest (`ocb/manifest.yaml`) defines the collector distribution:

```yaml
dist:
  name: otelcol-securityevents
  description: OpenTelemetry Collector with Security Event plugins for Dynatrace
  output_path: ./dist
  otelcol_version: v0.150.0
  module: github.com/dynatrace-oss/dynatrace-security-events-collector

receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.150.0

processors:
  - gomod: go.opentelemetry.io/collector/processor/batchprocessor v0.150.0
  - gomod: go.opentelemetry.io/collector/processor/memorylimiterprocessor v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/cumulativetodeltaprocessor v0.150.0
  # Custom: Security Event Processor
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor v0.0.0

exporters:
  - gomod: go.opentelemetry.io/collector/exporter/otlphttpexporter v0.150.0
  - gomod: go.opentelemetry.io/collector/exporter/otlpexporter v0.150.0
  - gomod: go.opentelemetry.io/collector/exporter/debugexporter v0.150.0
  # Custom: Security Event Exporter
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityEventExporter v0.0.0

replaces:
  - github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor => ./src/SecurityLogEventProcessor
  - github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityEventExporter => ./src/SecurityEventExporter
```

### Manifest sections

| Section | Description |
|---|---|
| `dist` | Output binary name, description, output path, and the base OTel Collector version. |
| `receivers` | List of receiver components to include. Each entry is a Go module path and version. |
| `processors` | List of processor components. The custom `securityevent` processor is listed here. |
| `exporters` | List of exporter components. The custom `securityevent` exporter is listed here. |
| `replaces` | Go module replacements. Maps the remote module path to a local directory for the monorepo plugins. |

### The `replaces` section

The `replaces` section is critical for the monorepo setup. The custom plugins are Go modules inside the repository (`src/SecurityLogEventProcessor` and `src/SecurityEventExporter`). Since they aren't published to a Go module proxy, OCB needs to resolve them locally:

```yaml
replaces:
  - github.com/dynatrace-oss/.../src/SecurityLogEventProcessor => ./src/SecurityLogEventProcessor
  - github.com/dynatrace-oss/.../src/SecurityEventExporter => ./src/SecurityEventExporter
```

OCB writes these as `replace` directives in the generated `go.mod`, so `go build` resolves the modules from the local filesystem.

---

## Building locally

### Using Make

```bash
# Build for current platform
make build

# Build for all supported platforms (linux, darwin, windows × amd64, arm64)
make build-all
```

The binary is output to `dist/otelcol-securityevents`.

### Using OCB directly

```bash
# Install OCB
go install go.opentelemetry.io/collector/cmd/builder@v0.150.0
mv $(go env GOPATH)/bin/builder $(go env GOPATH)/bin/ocb

# Build
ocb --config ocb/manifest.yaml --verbose
```

### Using the build script

```bash
./ocb/build.sh
```

The script installs OCB if not present, cleans previous builds, and runs the build.

### Cross-compilation

To build for a different platform:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ocb --config ocb/manifest.yaml
```

Supported targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

---

## Building with Docker

The provided Dockerfile performs a multi-stage build: it installs OCB, builds the collector, and copies the binary into a minimal Alpine image.

```bash
# Build for current platform
docker build -t dynatrace-oss/dynatrace-security-events-collector:latest -f docker/Dockerfile .

# Build multi-platform (requires Docker Buildx)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t dynatrace-oss/dynatrace-security-events-collector:latest \
  -f docker/Dockerfile \
  --push .
```

The Dockerfile:

1. Starts from `golang:1.24-alpine`
2. Copies the entire repository (including `src/`, `ocb/`)
3. Installs OCB and runs `ocb --config ocb/manifest.yaml`
4. Copies the binary and default config (`ocb/config.yaml`) into a minimal Alpine runtime image
5. Runs as non-root user `otelcol` on port 4317 (gRPC), 4318 (HTTP), 8888 (metrics)

---

## Customizing the manifest

### Adding components

To add a component, add its `gomod` entry to the appropriate section. For example, to add the `filelog` receiver:

```yaml
receivers:
  # ... existing receivers ...
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v0.150.0
```

All components must use the same OTel Collector version (the `otelcol_version` in the `dist` section). Mixing versions will cause dependency conflicts.

### Removing components

Remove the `gomod` entry from the manifest. OCB only includes components that are declared. Removing unused components reduces binary size and attack surface.

For example, if you don't need the Prometheus receiver:

```yaml
receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.150.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.150.0
  # Removed: prometheusreceiver
```

### Adding the security event plugins to an existing collector

If you already have a custom OTel Collector distribution and want to add the security event plugins, add the following to your existing manifest:

**1. Add the processor and exporter:**

```yaml
processors:
  # ... your existing processors ...
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor v0.0.0

exporters:
  # ... your existing exporters ...
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityEventExporter v0.0.0
```

**2. Add the replaces (for local builds):**

If you clone the repository as a subdirectory or use Git submodules:

```yaml
replaces:
  - github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor => ./path/to/SecurityLogEventProcessor
  - github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityEventExporter => ./path/to/SecurityEventExporter
```

**3. Add the k8sobjects receiver** (if not already included):

```yaml
receivers:
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.150.0
```

**4. Build:**

```bash
ocb --config your-manifest.yaml --verbose
```

### Pinning a specific version

When the plugins are published to a Go module proxy (future), you can pin a specific version instead of using `v0.0.0` with `replaces`:

```yaml
processors:
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor v1.0.0

exporters:
  - gomod: github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityEventExporter v1.0.0

# No replaces needed when using published modules
```

---

## Upgrading the OTel Collector version

To upgrade the base OTel Collector version:

1. Update `otelcol_version` in the `dist` section:

    ```yaml
    dist:
      otelcol_version: v0.150.0   # New version
    ```

2. Update **all** `gomod` entries to the same version:

    ```yaml
    receivers:
      - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.150.0
      # ... all other entries ...
    ```

3. Update the Go module dependencies in both plugin `go.mod` files (`src/SecurityLogEventProcessor/go.mod` and `src/SecurityEventExporter/go.mod`) to match the new OTel SDK versions.

4. Run `go mod tidy` in each plugin directory.

5. Rebuild and test.

All OTel components in the manifest must use the same version. The custom plugins must also be compatible with the OTel SDK version used by that collector version.

---

## CI/CD integration

The repository includes a GitHub Actions workflow (`.github/workflows/build-and-release.yaml`) that automates the full build pipeline:

| Stage | What it does |
|---|---|
| **Lint & test** | `go vet`, `golangci-lint`, unit tests with race detection and coverage |
| **Build plugins** | `go build ./...` for each plugin individually |
| **Build binaries** | OCB builds for 5 platform targets (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64) |
| **Build Docker** | Multi-arch Docker image pushed to GHCR (GitHub Container Registry) |
| **Security scan** | govulncheck, CodeQL, Trivy image scan |
| **SBOM** | SPDX and CycloneDX SBOMs generated from the Docker image |
| **Release** | GitHub Release with binaries, checksums, and SBOMs (on version tags) |

To trigger a release, push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Troubleshooting builds

### Common issues

**"module not found" for custom plugins:**

The `replaces` paths are relative to where OCB runs (the repository root). Make sure you run OCB from the repo root:

```bash
# Correct — from repo root
ocb --config ocb/manifest.yaml

# Wrong — from inside ocb/
cd ocb && ocb --config manifest.yaml
```

**Version mismatch errors:**

All OTel components must use the same version. If you see errors like `module requires go.opentelemetry.io/collector v0.150.0 but found v0.142.0`, check that every `gomod` entry in the manifest uses the same version.

**"cannot find package" during Docker build:**

The Dockerfile uses `COPY . .` to copy the entire repo into the build context. Make sure `src/`, `ocb/`, and `go.sum` files are not excluded by `.dockerignore`.
