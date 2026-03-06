# Makefile for building the Dynatrace Security Events Collector
# Requires: Go 1.24+, Docker (for image builds)

OCB_VERSION   ?= v0.145.0
IMAGE_NAME    ?= dynatrace-oss/dynatrace-security-events-collector
IMAGE_TAG     ?= latest
GOOS          ?= $(shell go env GOOS)
GOARCH        ?= $(shell go env GOARCH)
DIST_DIR      := dist
BINARY_NAME   := otelcol-securityevents

.PHONY: all install-ocb build build-all docker docker-buildx clean help test lint vet vulncheck

## Default target: build for current platform
all: build

## Install OCB (OpenTelemetry Collector Builder)
install-ocb:
	@echo "Installing OCB $(OCB_VERSION)..."
	go install go.opentelemetry.io/collector/cmd/builder@$(OCB_VERSION)
	mv $$(go env GOPATH)/bin/builder $$(go env GOPATH)/bin/ocb
	@echo "OCB installed at $$(which ocb)"

## Build collector binary for current platform
build: install-ocb
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 ocb --config ocb/manifest.yaml --verbose
	@echo "Binary: $(DIST_DIR)/$$(ls $(DIST_DIR)/ | head -1)"

## Build collector binaries for all supported platforms
build-all: install-ocb
	@echo "Building for all platforms..."
	@for platform in "linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64"; do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		echo "  Building for $${os}/$${arch}..."; \
		GOOS=$${os} GOARCH=$${arch} CGO_ENABLED=0 ocb --config ocb/manifest.yaml; \
		suffix="$${os}_$${arch}"; \
		if [ "$${os}" = "windows" ]; then \
			mv $(DIST_DIR)/$(BINARY_NAME)* $(DIST_DIR)/$(BINARY_NAME)_$${suffix}.exe 2>/dev/null || true; \
		else \
			mv $(DIST_DIR)/$(BINARY_NAME)* $(DIST_DIR)/$(BINARY_NAME)_$${suffix} 2>/dev/null || true; \
		fi; \
	done
	@echo "All binaries in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

## Build Docker image for current platform
docker:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) -f docker/Dockerfile .

## Build and push multi-platform Docker image
docker-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-f docker/Dockerfile \
		--push .

## Run unit tests for both plugins
test:
	@echo "Testing processor..."
	cd src/SecurityLogEventProcessor && go test -v -race -coverprofile=coverage.out ./...
	@echo "Testing exporter..."
	cd src/SecurityEventExporter && go test -v -race -coverprofile=coverage.out ./...

## Run go vet on both plugins
vet:
	cd src/SecurityLogEventProcessor && go vet ./...
	cd src/SecurityEventExporter && go vet ./...

## Run golangci-lint on both plugins
lint:
	cd src/SecurityLogEventProcessor && golangci-lint run --timeout=5m
	cd src/SecurityEventExporter && golangci-lint run --timeout=5m

## Run govulncheck on both plugins
vulncheck:
	cd src/SecurityLogEventProcessor && govulncheck ./...
	cd src/SecurityEventExporter && govulncheck ./...

## Clean build artifacts
clean:
	rm -rf $(DIST_DIR)

## Show help
help:
	@echo "Dynatrace Security Events Collector — Build Targets"
	@echo ""
	@echo "  Quality:"
	@echo "    make test          Run unit tests (both plugins, race detection)"
	@echo "    make vet           Run go vet (both plugins)"
	@echo "    make lint          Run golangci-lint (both plugins)"
	@echo "    make vulncheck     Run govulncheck (both plugins)"
	@echo ""
	@echo "  Build:"
	@echo "    make build         Build for current platform ($(GOOS)/$(GOARCH))"
	@echo "    make build-all     Build for all platforms (linux, darwin, windows)"
	@echo "    make docker        Build Docker image for current platform"
	@echo "    make docker-buildx Build & push multi-platform Docker image"
	@echo "    make install-ocb   Install OpenTelemetry Collector Builder"
	@echo "    make clean         Remove build artifacts"
	@echo ""
	@echo "  Variables:"
	@echo "    IMAGE_NAME=$(IMAGE_NAME)"
	@echo "    IMAGE_TAG=$(IMAGE_TAG)"
	@echo "    OCB_VERSION=$(OCB_VERSION)"
