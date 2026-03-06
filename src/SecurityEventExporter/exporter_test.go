package exporter

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()

	if factory == nil {
		t.Error("NewFactory() returned nil")
	}

	if factory.Type() != component.MustNewType("securityevent") {
		t.Errorf("Expected factory type 'securityevent', got %v", factory.Type())
	}
}

func TestCapabilities(t *testing.T) {
	exp := &securityEventExporter{}
	caps := exp.Capabilities()

	if caps.MutatesData != false {
		t.Error("Security event exporter should not mutate data")
	}
}

func TestStart(t *testing.T) {
	exp := &securityEventExporter{
		logger: zap.NewNop(),
		config: &Config{
			Endpoint: "https://example.com/events",
			Timeout:  30 * time.Second,
		},
		metrics: &exporterMetrics{
			logsReceived:       0,
			eventsExported:     0,
			eventsFailed:       0,
			conversionErrors:   0,
			httpErrors:         0,
			httpRequests:       0,
			httpDurations:      make([]time.Duration, 0),
			attributeConflicts: 0,
		},
	}

	ctx := context.Background()

	// Create a simple mock host
	host := &mockHost{}

	err := exp.Start(ctx, host)
	if err != nil {
		t.Errorf("Start() returned error: %v", err)
	}
}

func TestShutdown(t *testing.T) {
	exp := &securityEventExporter{
		logger: zap.NewNop(),
		metrics: &exporterMetrics{
			logsReceived:       0,
			eventsExported:     0,
			eventsFailed:       0,
			conversionErrors:   0,
			httpErrors:         0,
			httpRequests:       0,
			httpDurations:      make([]time.Duration, 0),
			attributeConflicts: 0,
		},
	}

	ctx := context.Background()

	err := exp.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() returned error: %v", err)
	}
}

func TestConsumeLogs(t *testing.T) {
	exp := &securityEventExporter{
		logger: zap.NewNop(),
		metrics: &exporterMetrics{
			logsReceived:       0,
			eventsExported:     0,
			eventsFailed:       0,
			conversionErrors:   0,
			httpErrors:         0,
			httpRequests:       0,
			httpDurations:      make([]time.Duration, 0),
			attributeConflicts: 0,
		},
	}

	ctx := context.Background()
	ld := plog.NewLogs()

	// Test with empty logs
	err := exp.ConsumeLogs(ctx, ld)
	if err != nil {
		t.Errorf("ConsumeLogs() returned error: %v", err)
	}
}

// mockHost is a simple mock implementation of component.Host
type mockHost struct{}

func (h *mockHost) ReportFatalError(err error) {}
func (h *mockHost) GetFactory(kind component.Kind, componentType component.Type) component.Factory {
	return nil
}
func (h *mockHost) GetExtensions() map[component.ID]component.Component {
	return nil
}
func (h *mockHost) GetExporters() map[component.ID]component.Component {
	return nil
}
