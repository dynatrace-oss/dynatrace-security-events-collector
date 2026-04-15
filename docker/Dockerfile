# Multi-stage Dockerfile for OpenTelemetry Collector with Security Event Plugins
# Produces a minimal, secure image for production Kubernetes deployments
#
# Build args:
#   TARGETARCH    - Target architecture (amd64, arm64) — set automatically by Docker Buildx
#   OCB_VERSION   - OpenTelemetry Collector Builder version
#   ALPINE_VERSION - Base Alpine version for the runtime image

# ============================================================
# Stage 1: Build the collector binary using OCB
# ============================================================
ARG GO_VERSION=1.25.9
ARG ALPINE_VERSION=3.21

FROM golang:${GO_VERSION}-alpine AS builder

ARG TARGETARCH
ARG OCB_VERSION=v0.150.0

# Install build dependencies
RUN apk add --no-cache git make

# Configure Go module settings
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
ENV GO111MODULE=on

WORKDIR /app

# Copy all source code (go.mod, go.sum, processor source, ocb manifests)
COPY . .

# Install OCB for the host architecture (needed to run the builder)
RUN go install go.opentelemetry.io/collector/cmd/builder@${OCB_VERSION} \
    && mv $(go env GOPATH)/bin/builder $(go env GOPATH)/bin/ocb

# Set cross-compilation environment for the target platform
ENV GOARCH=${TARGETARCH}
ENV GOOS=linux
ENV CGO_ENABLED=0

# Download dependencies
RUN go mod download || true

# Build the collector using OCB manifest
RUN ocb --config ocb/manifest.yaml --verbose

# ============================================================
# Stage 2: Minimal runtime image
# ============================================================
FROM alpine:${ALPINE_VERSION}

ARG TARGETARCH

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -s /bin/sh -u 10001 otelcol

# Create directories for config and data
RUN mkdir -p /etc/otelcol /var/lib/otelcol /tmp/otelcol \
    && chown -R otelcol:otelcol /etc/otelcol /var/lib/otelcol /tmp/otelcol

# Copy the collector binary from the build stage
# OCB may output with or without platform suffix depending on version
COPY --from=builder /app/dist /tmp/dist
RUN BINARY_NAME="otelcol-securityevents"; \
    if [ -f "/tmp/dist/${BINARY_NAME}_linux_${TARGETARCH}" ]; then \
        cp "/tmp/dist/${BINARY_NAME}_linux_${TARGETARCH}" /otelcol-securityevents; \
    elif [ -f "/tmp/dist/${BINARY_NAME}" ]; then \
        cp "/tmp/dist/${BINARY_NAME}" /otelcol-securityevents; \
    else \
        echo "Error: Collector binary not found. Available files:"; \
        ls -la /tmp/dist/; \
        exit 1; \
    fi && \
    rm -rf /tmp/dist

# Set ownership and permissions
RUN chown otelcol:otelcol /otelcol-securityevents \
    && chmod +x /otelcol-securityevents

# Copy default configuration
COPY ocb/config.yaml /etc/otelcol/config.yaml
RUN chown otelcol:otelcol /etc/otelcol/config.yaml

# Switch to non-root user
USER otelcol

# Expose collector ports
# 4317: OTLP gRPC receiver
# 4318: OTLP HTTP receiver
# 8888: Prometheus metrics (self-telemetry)
EXPOSE 4317 4318 8888

WORKDIR /etc/otelcol

ENTRYPOINT ["/otelcol-securityevents"]
CMD ["--config=/etc/otelcol/config.yaml"]

# Labels
LABEL maintainer="Henrik Rexed"
LABEL description="OpenTelemetry Collector with Security Event Processor and Exporter for Dynatrace"
LABEL org.opencontainers.image.source="https://github.com/dynatrace-oss/dynatrace-security-events-collector"
LABEL org.opencontainers.image.title="dynatrace-security-events-collector"
LABEL collector.version="0.150.0"
