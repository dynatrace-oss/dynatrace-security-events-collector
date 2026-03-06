package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// securityEventExporter is the implementation of the security event exporter
type securityEventExporter struct {
	config  *Config
	logger  *zap.Logger
	client  *http.Client
	metrics *exporterMetrics
}

// exporterMetrics contains the metrics for the security event exporter
type exporterMetrics struct {
	logsReceived       int64
	eventsExported     int64
	eventsFailed       int64
	conversionErrors   int64
	httpErrors         int64
	httpRequests       int64
	httpDurations      []time.Duration
	attributeConflicts int64
}

// NewFactory creates a new factory for the security event exporter
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		component.MustNewType("securityevent"),
		createDefaultConfig,
		exporter.WithLogs(createLogsExporter, component.StabilityLevelStable),
	)
}

// createDefaultConfig creates the default configuration for the security event exporter
func createDefaultConfig() component.Config {
	return &Config{
		Endpoint:      "http://localhost:8080/security-events",
		Timeout:       30 * time.Second,
		RetrySettings: createDefaultRetrySettings(),
		QueueSettings: createDefaultQueueSettings(),
		DefaultAttributes: map[string]interface{}{
			"source": "opentelemetry-collector",
		},
	}
}

// createLogsExporter creates a new logs exporter
func createLogsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Logs, error) {
	set.Logger.Info("Creating security event logs exporter")

	config := cfg.(*Config)
	set.Logger.Debug("Security event exporter configuration",
		zap.String("endpoint", config.Endpoint),
		zap.Duration("timeout", config.Timeout),
		zap.Int("header_count", len(config.Headers)),
		zap.Int("default_attribute_count", len(config.DefaultAttributes)))

	// Validate configuration
	if err := config.Validate(); err != nil {
		set.Logger.Error("Invalid configuration for security event exporter", zap.Error(err))
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	set.Logger.Debug("Configuration validation passed")

	// Create HTTP client
	client := &http.Client{
		Timeout: config.Timeout,
	}

	set.Logger.Debug("Created HTTP client",
		zap.Duration("timeout", config.Timeout))

	// Create exporter instance
	exp := &securityEventExporter{
		config: config,
		logger: set.Logger,
		client: client,
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

	set.Logger.Info("Successfully created security event logs exporter")
	return exp, nil
}

// Capabilities returns the capabilities of the exporter
func (e *securityEventExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// Start starts the exporter
func (e *securityEventExporter) Start(ctx context.Context, host component.Host) error {
	e.logger.Info("Starting security event exporter",
		zap.String("endpoint", e.config.Endpoint),
		zap.Duration("timeout", e.config.Timeout),
		zap.Int("header_count", len(e.config.Headers)),
		zap.Int("default_attribute_count", len(e.config.DefaultAttributes)))

	e.logger.Debug("Security event exporter configuration",
		zap.Any("retry_settings", e.config.RetrySettings),
		zap.Any("queue_settings", e.config.QueueSettings))

	e.logger.Debug("Initialized telemetry metrics",
		zap.Int64("logs_received", e.metrics.logsReceived),
		zap.Int64("events_exported", e.metrics.eventsExported),
		zap.Int64("events_failed", e.metrics.eventsFailed),
		zap.Int64("conversion_errors", e.metrics.conversionErrors),
		zap.Int64("http_requests", e.metrics.httpRequests),
		zap.Int64("http_errors", e.metrics.httpErrors),
		zap.Int64("attribute_conflicts", e.metrics.attributeConflicts))

	return nil
}

// Shutdown shuts down the exporter
func (e *securityEventExporter) Shutdown(ctx context.Context) error {
	e.logger.Info("Shutting down security event exporter")

	// Report final metrics
	e.logger.Info("Final telemetry metrics",
		zap.Int64("logs_received", e.metrics.logsReceived),
		zap.Int64("events_exported", e.metrics.eventsExported),
		zap.Int64("events_failed", e.metrics.eventsFailed),
		zap.Int64("conversion_errors", e.metrics.conversionErrors),
		zap.Int64("http_requests", e.metrics.httpRequests),
		zap.Int64("http_errors", e.metrics.httpErrors),
		zap.Int64("attribute_conflicts", e.metrics.attributeConflicts),
		zap.Int("http_duration_samples", len(e.metrics.httpDurations)))

	// Calculate and report average HTTP duration if we have samples
	if len(e.metrics.httpDurations) > 0 {
		totalDuration := time.Duration(0)
		for _, duration := range e.metrics.httpDurations {
			totalDuration += duration
		}
		avgDuration := totalDuration / time.Duration(len(e.metrics.httpDurations))
		e.logger.Info("HTTP request performance metrics",
			zap.Duration("average_duration", avgDuration),
			zap.Int("sample_count", len(e.metrics.httpDurations)))
	}

	e.logger.Debug("Security event exporter shutdown completed")
	return nil
}

// ConsumeLogs processes the incoming logs and converts them to security events
func (e *securityEventExporter) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	totalResourceLogs := ld.ResourceLogs().Len()
	totalLogRecords := 0
	conversionErrors := 0

	e.logger.Debug("Processing logs batch",
		zap.Int("resource_logs_count", totalResourceLogs))

	// Collect all security events to batch them
	var securityEvents []map[string]interface{}

	// Process each resource log
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		resourceLog := ld.ResourceLogs().At(i)

		e.logger.Debug("Processing resource log",
			zap.Int("resource_index", i),
			zap.Int("scope_logs_count", resourceLog.ScopeLogs().Len()))

		// Process each scope log
		for j := 0; j < resourceLog.ScopeLogs().Len(); j++ {
			scopeLog := resourceLog.ScopeLogs().At(j)
			logRecordsCount := scopeLog.LogRecords().Len()
			totalLogRecords += logRecordsCount

			e.logger.Debug("Processing scope log",
				zap.Int("scope_index", j),
				zap.Int("log_records_count", logRecordsCount))

			// Process each log record
			for k := 0; k < scopeLog.LogRecords().Len(); k++ {
				logRecord := scopeLog.LogRecords().At(k)

				e.logger.Debug("Processing log record",
					zap.Int("log_index", k),
					zap.String("severity", logRecord.SeverityText()),
					zap.Int64("timestamp", logRecord.Timestamp().AsTime().Unix()))

				// Convert log to security event
				securityEvent, err := e.convertLogToSecurityEvent(logRecord, resourceLog.Resource())
				if err != nil {
					e.logger.Error("Failed to convert log to security event",
						zap.Error(err),
						zap.Int("resource_index", i),
						zap.Int("scope_index", j),
						zap.Int("log_index", k),
						zap.String("severity", logRecord.SeverityText()))
					conversionErrors++
					continue
				}

				e.logger.Debug("Successfully converted log to security event",
					zap.Int("event_field_count", len(securityEvent)))

				// Add to batch
				securityEvents = append(securityEvents, securityEvent)
			}
		}
	}

	// Update metrics
	e.metrics.logsReceived += int64(totalLogRecords)
	e.metrics.conversionErrors += int64(conversionErrors)

	// Send all security events in a single batch
	if len(securityEvents) > 0 {
		e.logger.Debug("Sending batch of security events",
			zap.Int("event_count", len(securityEvents)))

		if err := e.sendSecurityEventBatch(ctx, securityEvents); err != nil {
			e.logger.Error("Failed to send security event batch",
				zap.Error(err),
				zap.Int("event_count", len(securityEvents)),
				zap.String("endpoint", e.config.Endpoint))
			e.metrics.eventsFailed += int64(len(securityEvents))
			return err
		}

		e.metrics.eventsExported += int64(len(securityEvents))
		e.logger.Debug("Successfully sent security event batch",
			zap.Int("event_count", len(securityEvents)))
	}

	successfulEvents := len(securityEvents)
	e.logger.Info("Completed processing logs batch",
		zap.Int("total_resource_logs", totalResourceLogs),
		zap.Int("total_log_records", totalLogRecords),
		zap.Int("successful_events", successfulEvents),
		zap.Int("failed_events", conversionErrors),
		zap.Int("http_requests", 1))

	return nil
}

// convertLogToSecurityEvent converts an OpenTelemetry log record to a security event
func (e *securityEventExporter) convertLogToSecurityEvent(logRecord plog.LogRecord, resource pcommon.Resource) (map[string]interface{}, error) {
	e.logger.Debug("Starting log to security event conversion")

	// Create base security event
	securityEvent := make(map[string]interface{})

	// Add default attributes (excluding source)
	defaultAttrCount := 0
	for key, value := range e.config.DefaultAttributes {
		// Skip source field
		if key == "source" {
			continue
		}
		securityEvent[key] = value
		defaultAttrCount++
	}
	e.logger.Debug("Added default attributes",
		zap.Int("count", defaultAttrCount))

	// Add resource attributes (at root level)
	resourceAttrCount := 0
	resource.Attributes().Range(func(key string, value pcommon.Value) bool {
		securityEvent[key] = value.AsString()
		resourceAttrCount++
		e.logger.Debug("Added resource attribute",
			zap.String("key", key),
			zap.String("value", value.AsString()))
		return true
	})
	e.logger.Debug("Added resource attributes",
		zap.Int("count", resourceAttrCount))

	// Add log record attributes (at root level)
	// Check for conflicts with resource attributes
	logAttrCount := 0
	conflictCount := 0
	logRecord.Attributes().Range(func(key string, value pcommon.Value) bool {
		// Check if this key already exists (from resource attributes)
		if _, exists := securityEvent[key]; exists {
			e.logger.Warn("Attribute key conflict detected",
				zap.String("key", key),
				zap.String("resource_value", fmt.Sprintf("%v", securityEvent[key])),
				zap.String("log_value", value.AsString()),
				zap.String("message", "Log attribute will overwrite resource attribute"))
			conflictCount++
			e.metrics.attributeConflicts++
		}
		securityEvent[key] = value.AsString()
		logAttrCount++
		e.logger.Debug("Added log attribute",
			zap.String("key", key),
			zap.String("value", value.AsString()))
		return true
	})
	e.logger.Debug("Added log attributes",
		zap.Int("count", logAttrCount),
		zap.Int("conflicts", conflictCount))

	// Add log record fields
	timestamp := logRecord.Timestamp().AsTime()
	securityEvent["timestamp"] = timestamp.Format(time.RFC3339)

	e.logger.Debug("Added log record fields",
		zap.String("timestamp", timestamp.Format(time.RFC3339)))

	// Add trace and span information if available
	if traceID := logRecord.TraceID(); !traceID.IsEmpty() {
		securityEvent["trace_id"] = traceID.String()
		e.logger.Debug("Added trace ID", zap.String("trace_id", traceID.String()))
	}
	if spanID := logRecord.SpanID(); !spanID.IsEmpty() {
		securityEvent["span_id"] = spanID.String()
		e.logger.Debug("Added span ID", zap.String("span_id", spanID.String()))
	}

	// Log body is intentionally excluded from the security event payload
	e.logger.Debug("Log body excluded from security event payload")

	totalFields := len(securityEvent)
	e.logger.Debug("Completed log to security event conversion",
		zap.Int("total_fields", totalFields))

	return securityEvent, nil
}

// truncateString truncates a string to the specified length and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// sendSecurityEventBatch sends a batch of security events to the configured endpoint
func (e *securityEventExporter) sendSecurityEventBatch(ctx context.Context, securityEvents []map[string]interface{}) error {
	e.logger.Debug("Starting to send security event batch",
		zap.String("endpoint", e.config.Endpoint),
		zap.Int("event_count", len(securityEvents)))

	// Marshal security events to JSON array
	jsonData, err := json.Marshal(securityEvents)
	if err != nil {
		e.logger.Error("Failed to marshal security event batch to JSON",
			zap.Error(err),
			zap.Int("event_count", len(securityEvents)))
		e.metrics.httpErrors++
		return fmt.Errorf("failed to marshal security event batch: %w", err)
	}

	jsonSize := len(jsonData)
	e.logger.Debug("Successfully marshaled security event batch to JSON",
		zap.Int("json_size_bytes", jsonSize),
		zap.Int("event_count", len(securityEvents)),
		zap.String("json_preview", truncateString(string(jsonData), 200)))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", e.config.Endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		e.logger.Error("Failed to create HTTP request for batch",
			zap.Error(err),
			zap.String("endpoint", e.config.Endpoint),
			zap.String("method", "POST"))
		e.metrics.httpErrors++
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	e.logger.Debug("Created HTTP request for batch",
		zap.String("url", req.URL.String()),
		zap.String("method", req.Method))

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	headerCount := 1 // Content-Type header
	for key, value := range e.config.Headers {
		req.Header.Set(key, string(value))
		headerCount++
		e.logger.Debug("Added custom header",
			zap.String("header_name", key),
			zap.Bool("is_sensitive", isSensitiveHeader(key)))
	}

	e.logger.Debug("Set HTTP headers for batch",
		zap.Int("total_headers", headerCount))

	// Send request
	e.logger.Debug("Sending HTTP request for batch",
		zap.String("endpoint", e.config.Endpoint),
		zap.Duration("timeout", e.config.Timeout),
		zap.Int("event_count", len(securityEvents)))

	startTime := time.Now()
	resp, err := e.client.Do(req)
	requestDuration := time.Since(startTime)

	// Update metrics
	e.metrics.httpRequests++
	e.metrics.httpDurations = append(e.metrics.httpDurations, requestDuration)

	if err != nil {
		e.logger.Error("Failed to send HTTP request for batch",
			zap.Error(err),
			zap.String("endpoint", e.config.Endpoint),
			zap.Duration("request_duration", requestDuration),
			zap.Duration("timeout", e.config.Timeout),
			zap.Int("event_count", len(securityEvents)))
		e.metrics.httpErrors++
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	e.logger.Debug("Received HTTP response for batch",
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status),
		zap.Duration("request_duration", requestDuration),
		zap.Int64("content_length", resp.ContentLength),
		zap.Int("event_count", len(securityEvents)))

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.logger.Error("HTTP request failed with non-success status for batch",
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status),
			zap.String("endpoint", e.config.Endpoint),
			zap.Duration("request_duration", requestDuration),
			zap.Int("event_count", len(securityEvents)))

		// Try to read response body for additional error details
		if resp.Body != nil {
			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil && len(body) > 0 {
				e.logger.Error("HTTP error response body for batch",
					zap.String("response_body", truncateString(string(body), 500)))
			}
		}

		e.metrics.httpErrors++
		return fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	e.logger.Debug("Successfully sent security event batch",
		zap.Int("status_code", resp.StatusCode),
		zap.Duration("request_duration", requestDuration),
		zap.Int("json_size_bytes", jsonSize),
		zap.Int("event_count", len(securityEvents)))

	return nil
}

// sendSecurityEvent sends a single security event to the configured endpoint (deprecated - use batch method)
func (e *securityEventExporter) sendSecurityEvent(ctx context.Context, securityEvent map[string]interface{}) error {
	e.logger.Debug("Starting to send security event",
		zap.String("endpoint", e.config.Endpoint),
		zap.Int("event_field_count", len(securityEvent)))

	// Marshal security event to JSON
	jsonData, err := json.Marshal(securityEvent)
	if err != nil {
		e.logger.Error("Failed to marshal security event to JSON",
			zap.Error(err),
			zap.Int("event_field_count", len(securityEvent)))
		return fmt.Errorf("failed to marshal security event: %w", err)
	}

	jsonSize := len(jsonData)
	e.logger.Debug("Successfully marshaled security event to JSON",
		zap.Int("json_size_bytes", jsonSize),
		zap.String("json_preview", truncateString(string(jsonData), 200)))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", e.config.Endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		e.logger.Error("Failed to create HTTP request",
			zap.Error(err),
			zap.String("endpoint", e.config.Endpoint),
			zap.String("method", "POST"))
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	e.logger.Debug("Created HTTP request",
		zap.String("url", req.URL.String()),
		zap.String("method", req.Method))

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	headerCount := 1 // Content-Type header
	for key, value := range e.config.Headers {
		req.Header.Set(key, string(value))
		headerCount++
		e.logger.Debug("Added custom header",
			zap.String("header_name", key),
			zap.Bool("is_sensitive", isSensitiveHeader(key)))
	}

	e.logger.Debug("Set HTTP headers",
		zap.Int("total_headers", headerCount))

	// Send request
	e.logger.Debug("Sending HTTP request",
		zap.String("endpoint", e.config.Endpoint),
		zap.Duration("timeout", e.config.Timeout))

	startTime := time.Now()
	resp, err := e.client.Do(req)
	requestDuration := time.Since(startTime)

	if err != nil {
		e.logger.Error("Failed to send HTTP request",
			zap.Error(err),
			zap.String("endpoint", e.config.Endpoint),
			zap.Duration("request_duration", requestDuration),
			zap.Duration("timeout", e.config.Timeout))
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	e.logger.Debug("Received HTTP response",
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status),
		zap.Duration("request_duration", requestDuration),
		zap.Int64("content_length", resp.ContentLength))

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.logger.Error("HTTP request failed with non-success status",
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status),
			zap.String("endpoint", e.config.Endpoint),
			zap.Duration("request_duration", requestDuration))

		// Try to read response body for additional error details
		if resp.Body != nil {
			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil && len(body) > 0 {
				e.logger.Error("HTTP error response body",
					zap.String("response_body", truncateString(string(body), 500)))
			}
		}

		return fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	e.logger.Debug("Successfully sent security event",
		zap.Int("status_code", resp.StatusCode),
		zap.Duration("request_duration", requestDuration),
		zap.Int("json_size_bytes", jsonSize))

	return nil
}

// isSensitiveHeader checks if a header name contains sensitive information
func isSensitiveHeader(headerName string) bool {
	sensitiveHeaders := []string{"authorization", "cookie", "x-api-key", "x-auth-token"}
	headerLower := strings.ToLower(headerName)
	for _, sensitive := range sensitiveHeaders {
		if strings.Contains(headerLower, sensitive) {
			return true
		}
	}
	return false
}
