package securityevent

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor/internal/openreports"
)

// securityEventProcessor processes logs and transforms them into security events
type securityEventProcessor struct {
	logger      *zap.Logger
	config      *Config
	openReports *openreports.Processor
	metrics     *processorMetrics
}

// processorMetrics holds the metrics for the processor
type processorMetrics struct {
	incomingLogs     metric.Int64Counter
	outgoingLogs     metric.Int64Counter
	droppedLogs      metric.Int64Counter
	processingErrors metric.Int64Counter
}

const (
	metricPrefix = "processor_securityevent_"

	metricIncomingLogs     = metricPrefix + "incoming_logs_total"
	metricOutgoingLogs     = metricPrefix + "outgoing_logs_total"
	metricDroppedLogs      = metricPrefix + "dropped_logs_total"
	metricProcessingErrors = metricPrefix + "processing_errors_total"
)

// newSecurityEventProcessor creates a new security event processor
func newSecurityEventProcessor(logger *zap.Logger, config *Config, settings component.TelemetrySettings) (*securityEventProcessor, error) {
	processor := &securityEventProcessor{
		logger: logger,
		config: config,
	}

	// Initialize metrics
	meter := settings.MeterProvider.Meter("github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor")
	metrics, err := createProcessorMetrics(meter)
	if err != nil {
		return nil, err
	}
	processor.metrics = metrics

	// Initialize OpenReports processor if enabled
	if config.Processors.OpenReports.Enabled {
		var err error
		processor.openReports, err = openreports.NewProcessor(logger, &config.Processors.OpenReports)
		if err != nil {
			return nil, err
		}
		processor.logger.Info("OpenReports processor enabled")
	}

	return processor, nil
}

// createProcessorMetrics creates the metrics for the processor
func createProcessorMetrics(meter metric.Meter) (*processorMetrics, error) {
	incomingLogs, err := meter.Int64Counter(
		metricIncomingLogs,
		metric.WithDescription("Total number of incoming logs processed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	outgoingLogs, err := meter.Int64Counter(
		metricOutgoingLogs,
		metric.WithDescription("Total number of outgoing logs produced"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	droppedLogs, err := meter.Int64Counter(
		metricDroppedLogs,
		metric.WithDescription("Total number of logs dropped during processing"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	processingErrors, err := meter.Int64Counter(
		metricProcessingErrors,
		metric.WithDescription("Total number of processing errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	return &processorMetrics{
		incomingLogs:     incomingLogs,
		outgoingLogs:     outgoingLogs,
		droppedLogs:      droppedLogs,
		processingErrors: processingErrors,
	}, nil
}

// processLogs processes the incoming logs and transforms them into security events
//
//nolint:gocyclo // Complex transformation logic with multiple nested iterations and conditionals
func (p *securityEventProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	// Count incoming logs
	incomingCount := int64(0)
	outgoingCount := int64(0)
	droppedCount := int64(0)

	p.logger.Debug("Processing logs batch",
		zap.Int("resource_logs_count", ld.ResourceLogs().Len()))

	resourceLogs := ld.ResourceLogs()

	for i := 0; i < resourceLogs.Len(); i++ {
		resourceLog := resourceLogs.At(i)
		scopeLogs := resourceLog.ScopeLogs()

		for j := 0; j < scopeLogs.Len(); j++ {
			scopeLog := scopeLogs.At(j)
			logRecords := scopeLog.LogRecords()

			// Collect records to replace in first pass
			type replacement struct {
				index      int
				newRecords []plog.LogRecord
			}
			var replacements []replacement

			// Track which indices will be replaced to avoid double-counting
			replacementIndices := make(map[int]bool)

			p.logger.Debug("Processing scope logs",
				zap.Int("scope_index", j),
				zap.Int("log_records_count", logRecords.Len()))

			// First pass: identify records that need to be expanded
			for k := 0; k < logRecords.Len(); k++ {
				logRecord := logRecords.At(k)
				incomingCount++ // Count each incoming log record

				p.logger.Debug("Processing log record",
					zap.Int("record_index", k),
					zap.String("trace_id", logRecord.TraceID().String()),
					zap.String("span_id", logRecord.SpanID().String()),
					zap.Bool("openreports_enabled", p.openReports != nil))

				// Process with OpenReports if enabled
				if p.openReports != nil {
					// Quick check if this log matches OpenReports before processing
					if !isOpenReportsLog(&logRecord) {
						p.logger.Debug("Log record does not match OpenReports - skipping processor",
							zap.Int("record_index", k),
							zap.String("trace_id", logRecord.TraceID().String()),
							zap.String("reason", "not_openreports_format"))
						// Log passes through unchanged
						outgoingCount++
						continue
					}

					p.logger.Debug("Log record matches OpenReports processor - proceeding with transformation",
						zap.Int("record_index", k),
						zap.String("trace_id", logRecord.TraceID().String()))

					newRecords, err := p.openReports.ProcessLogRecord(ctx, &logRecord, resourceLog.Resource(), scopeLog)
					if err != nil {
						p.logger.Warn("Failed to process log record with OpenReports processor",
							zap.Error(err))
						p.metrics.processingErrors.Add(ctx, 1,
							metric.WithAttributes(attribute.String("error_type", "processing_error")))
						// Continue processing other records, but this log is effectively dropped
						droppedCount++
						continue
					}

					// If new records were created (expanded), mark for replacement
					if len(newRecords) > 0 {
						p.logger.Debug("Log record expanded into multiple security events",
							zap.Int("record_index", k),
							zap.Int("expanded_count", len(newRecords)),
							zap.String("trace_id", logRecord.TraceID().String()))
						replacements = append(replacements, replacement{
							index:      k,
							newRecords: newRecords,
						})
						replacementIndices[k] = true
						// Note: outgoingCount will be incremented in the replacement pass for expanded logs
					} else {
						// Log was processed but not expanded (not an OpenReports log or filtered out)
						p.logger.Debug("Log record processed but not expanded - passing through unchanged",
							zap.Int("record_index", k),
							zap.String("reason", "not_openreports_or_filtered"),
							zap.String("trace_id", logRecord.TraceID().String()))
						// This log passes through unchanged, so it counts as outgoing
						outgoingCount++
					}
				} else {
					// No processor enabled, log passes through unchanged
					p.logger.Debug("No OpenReports processor enabled - log passes through unchanged",
						zap.Int("record_index", k))
					outgoingCount++
				}
			}

			// Second pass: replace records
			if len(replacements) > 0 {
				p.logger.Debug("Replacing expanded log records",
					zap.Int("replacements_count", len(replacements)),
					zap.Int("original_records", logRecords.Len()))

				// Build new log records array
				newLogRecords := plog.NewLogRecordSlice()

				// Copy records, replacing expanded ones
				replacementIndex := 0
				for k := 0; k < logRecords.Len(); k++ {
					// Check if this index needs replacement
					if replacementIndex < len(replacements) && replacements[replacementIndex].index == k {
						// Replace with new records (expanded)
						for _, newRecord := range replacements[replacementIndex].newRecords {
							insertedRecord := newLogRecords.AppendEmpty()
							newRecord.CopyTo(insertedRecord)
							outgoingCount++ // Count each expanded log
						}
						replacementIndex++
					} else if !replacementIndices[k] {
						// Copy original record (unchanged) - only count if not already counted in first pass
						// (Actually, if we're in this pass, we need to rebuild everything, so we count all)
						originalRecord := logRecords.At(k)
						insertedRecord := newLogRecords.AppendEmpty()
						originalRecord.CopyTo(insertedRecord)
						// Note: We already counted this in the first pass, so we don't count again
					}
				}

				// Clear original and move new records
				logRecords.RemoveIf(func(plog.LogRecord) bool { return true })
				newLogRecords.MoveAndAppendTo(logRecords)

				p.logger.Debug("Log records replacement completed",
					zap.Int("new_records_count", logRecords.Len()),
					zap.Int("outgoing_count", int(outgoingCount)))
			}
		}
	}

	p.logger.Debug("Batch processing completed",
		zap.Int64("incoming_logs", incomingCount),
		zap.Int64("outgoing_logs", outgoingCount),
		zap.Int64("dropped_logs", droppedCount))

	// Record metrics
	if incomingCount > 0 {
		p.metrics.incomingLogs.Add(ctx, incomingCount)
	}
	if outgoingCount > 0 {
		p.metrics.outgoingLogs.Add(ctx, outgoingCount)
	}
	if droppedCount > 0 {
		p.metrics.droppedLogs.Add(ctx, droppedCount)
	}

	return ld, nil
}

// isOpenReportsLog performs a quick check to determine if a log record matches OpenReports format
// k8sobjects receiver puts Report CRD data in the log body as a Map, so we check both body and attributes
func isOpenReportsLog(logRecord *plog.LogRecord) bool {
	attrs := logRecord.Attributes()
	body := logRecord.Body()

	// Try to get kind and apiVersion from body Map first (k8sobjects receiver format)
	var kindVal pcommon.Value
	var apiVersionVal pcommon.Value
	var kindExists, apiVersionExists bool

	if body.Type() == pcommon.ValueTypeMap {
		bodyMap := body.Map()
		kindVal, kindExists = bodyMap.Get("kind")
		apiVersionVal, apiVersionExists = bodyMap.Get("apiVersion")
	}

	// Fall back to attributes if not found in body
	if !kindExists {
		kindVal, kindExists = attrs.Get("kind")
	}
	if !apiVersionExists {
		apiVersionVal, apiVersionExists = attrs.Get("apiVersion")
	}

	// Check kind field
	if !kindExists || kindVal.AsString() != "Report" {
		return false
	}

	// Check apiVersion field
	if !apiVersionExists || apiVersionVal.AsString() != "openreports.io/v1alpha1" {
		return false
	}

	return true
}
