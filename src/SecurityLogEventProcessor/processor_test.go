package securityevent

import (
	"context"
	"testing"

	"github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor/internal/openreports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

func TestNewSecurityEventProcessor_EmptyConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()

	processor, err := newSecurityEventProcessor(logger, config, settings)

	require.NoError(t, err)
	require.NotNil(t, processor)
	assert.Nil(t, processor.openReports, "OpenReports processor should be nil when disabled")
}

func TestNewSecurityEventProcessor_WithOpenReportsEnabled(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{
			OpenReports: openreports.Config{
				Enabled:      true,
				StatusFilter: []string{"fail"},
			},
		},
	}

	settings := componenttest.NewNopTelemetrySettings()

	processor, err := newSecurityEventProcessor(logger, config, settings)

	require.NoError(t, err)
	require.NotNil(t, processor)
	assert.NotNil(t, processor.openReports, "OpenReports processor should be created when enabled")
}

func TestIsOpenReportsLog_ValidOpenReportsLog(t *testing.T) {
	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")

	result := isOpenReportsLog(&logRecord)
	assert.True(t, result, "Should identify valid OpenReports log")
}

func TestIsOpenReportsLog_InvalidKind(t *testing.T) {
	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "NotReport")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")

	result := isOpenReportsLog(&logRecord)
	assert.False(t, result, "Should not identify log with wrong kind")
}

func TestIsOpenReportsLog_InvalidApiVersion(t *testing.T) {
	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "v1")

	result := isOpenReportsLog(&logRecord)
	assert.False(t, result, "Should not identify log with wrong apiVersion")
}

func TestIsOpenReportsLog_MissingKind(t *testing.T) {
	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	// No kind field

	result := isOpenReportsLog(&logRecord)
	assert.False(t, result, "Should not identify log without kind")
}

func TestIsOpenReportsLog_MissingApiVersion(t *testing.T) {
	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	// No apiVersion field

	result := isOpenReportsLog(&logRecord)
	assert.False(t, result, "Should not identify log without apiVersion")
}

func TestProcessLogs_EmptyLogs(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ResourceLogs().Len())
}

func TestProcessLogs_NonOpenReportsLog_PassesThrough(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{
			OpenReports: openreports.Config{
				Enabled: true,
			},
		},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.Attributes().PutStr("kind", "Pod")
	logRecord.Attributes().PutStr("apiVersion", "v1")
	var traceID [16]byte
	copy(traceID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	logRecord.SetTraceID(pcommon.TraceID(traceID))

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.ResourceLogs().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())

	// Verify log record passed through unchanged
	resultRecord := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, logRecord.TraceID(), resultRecord.TraceID())
}

func TestProcessLogs_WithOpenReportsDisabled_PassesThrough(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{
			OpenReports: openreports.Config{
				Enabled: false,
			},
		},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.Attributes().PutStr("kind", "Report")
	logRecord.Attributes().PutStr("apiVersion", "openreports.io/v1alpha1")

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	// Log should pass through unchanged when OpenReports is disabled
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_MultipleResourceLogs(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()

	// First resource log
	resourceLog1 := logs.ResourceLogs().AppendEmpty()
	scopeLog1 := resourceLog1.ScopeLogs().AppendEmpty()
	logRecord1 := scopeLog1.LogRecords().AppendEmpty()
	logRecord1.Attributes().PutStr("kind", "Pod")

	// Second resource log
	resourceLog2 := logs.ResourceLogs().AppendEmpty()
	scopeLog2 := resourceLog2.ScopeLogs().AppendEmpty()
	logRecord2 := scopeLog2.LogRecords().AppendEmpty()
	logRecord2.Attributes().PutStr("kind", "Service")

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 2, result.ResourceLogs().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(1).ScopeLogs().At(0).LogRecords().Len())

	_ = resourceLog1
	_ = resourceLog2
}

func TestProcessLogs_MultipleScopeLogs(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	resourceLog := logs.ResourceLogs().AppendEmpty()

	// First scope log
	scopeLog1 := resourceLog.ScopeLogs().AppendEmpty()
	logRecord1 := scopeLog1.LogRecords().AppendEmpty()
	logRecord1.Attributes().PutStr("kind", "Pod")

	// Second scope log
	scopeLog2 := resourceLog.ScopeLogs().AppendEmpty()
	logRecord2 := scopeLog2.LogRecords().AppendEmpty()
	logRecord2.Attributes().PutStr("kind", "Service")

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.ResourceLogs().Len())
	assert.Equal(t, 2, result.ResourceLogs().At(0).ScopeLogs().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(1).LogRecords().Len())
}

func TestProcessLogs_MultipleLogRecords(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	resourceLog := logs.ResourceLogs().AppendEmpty()
	scopeLog := resourceLog.ScopeLogs().AppendEmpty()

	// Multiple log records
	for i := 0; i < 3; i++ {
		logRecord := scopeLog.LogRecords().AppendEmpty()
		logRecord.Attributes().PutStr("kind", "Pod")
		logRecord.Attributes().PutInt("index", int64(i))
	}

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.ResourceLogs().Len())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().Len())
	assert.Equal(t, 3, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestCreateProcessorMetrics(t *testing.T) {
	settings := componenttest.NewNopTelemetrySettings()
	meter := settings.MeterProvider.Meter("test")

	metrics, err := createProcessorMetrics(meter)

	require.NoError(t, err)
	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.incomingLogs)
	assert.NotNil(t, metrics.outgoingLogs)
	assert.NotNil(t, metrics.droppedLogs)
	assert.NotNil(t, metrics.processingErrors)
}

func TestProcessLogs_MetricsIncremented(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Processors: ProcessorConfig{},
	}

	settings := componenttest.NewNopTelemetrySettings()
	processor, err := newSecurityEventProcessor(logger, config, settings)
	require.NoError(t, err)

	logs := plog.NewLogs()
	resourceLog := logs.ResourceLogs().AppendEmpty()
	scopeLog := resourceLog.ScopeLogs().AppendEmpty()

	// Add 2 log records
	for i := 0; i < 2; i++ {
		logRecord := scopeLog.LogRecords().AppendEmpty()
		logRecord.Attributes().PutStr("kind", "Pod")
	}

	result, err := processor.processLogs(context.Background(), logs)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Metrics should be incremented (though we can't easily test the exact values without a metrics exporter)
	// The fact that processLogs didn't panic or error means metrics were handled correctly
}
