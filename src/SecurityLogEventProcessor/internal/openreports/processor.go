package openreports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// Constants for repeated string literals
const (
	resultStatusFail       = "fail"
	resultStatusPass       = "pass"
	resultStatusError      = "error"
	resultStatusSkip       = "skip"
	riskLevelHigh          = "HIGH"
	riskLevelMedium        = "MEDIUM"
	riskLevelLow           = "LOW"
	riskLevelCritical      = "CRITICAL"
	complianceCompliant    = "COMPLIANT"
	complianceNonCompliant = "NON_COMPLIANT"
	k8sKindPod             = "Pod"
	k8sKindDeployment      = "Deployment"
	missingValue           = "missing"
)

// Processor handles transformation of OpenReports logs into security events
type Processor struct {
	logger *zap.Logger
	config *Config
	// processedResults tracks which results have been processed per pod/workload
	// Key: pod identifier (scope.uid or scope.name+scope.namespace)
	// Value: set of processed result identifiers (hash of result JSON)
	processedResults map[string]map[string]bool
	mu               sync.RWMutex
}

// NewProcessor creates a new OpenReports processor
func NewProcessor(logger *zap.Logger, config *Config) (*Processor, error) {
	return &Processor{
		logger:           logger,
		config:           config,
		processedResults: make(map[string]map[string]bool),
	}, nil
}

// ProcessLogRecord processes a single log record and transforms it into multiple security events
// Returns a slice of new log records (one per result) or nil if this is not an OpenReports log
//
//nolint:gocyclo // Complex log parsing and transformation with nested conditionals and loops
func (p *Processor) ProcessLogRecord(ctx context.Context, logRecord *plog.LogRecord, resource pcommon.Resource, scopeLogs plog.ScopeLogs) ([]plog.LogRecord, error) {
	// k8sobjects receiver puts Report CRD data in the log body as a Map
	// Check both body Map and attributes for compatibility
	attrs := logRecord.Attributes()
	body := logRecord.Body()

	// Try to get kind and apiVersion from body Map first (k8sobjects receiver format)
	var bodyMap pcommon.Map
	var kindVal pcommon.Value
	var apiVersionVal pcommon.Value
	var kindExists, apiVersionExists bool

	if body.Type() == pcommon.ValueTypeMap {
		bodyMap = body.Map()
		kindVal, kindExists = bodyMap.Get("kind")
		apiVersionVal, apiVersionExists = bodyMap.Get("apiVersion")
		p.logger.Debug("Checking log body Map for OpenReports data",
			zap.Bool("body_is_map", true),
			zap.Bool("kind_exists_in_body", kindExists),
			zap.Bool("apiVersion_exists_in_body", apiVersionExists))
	}

	// Fall back to attributes if not found in body
	if !kindExists {
		kindVal, kindExists = attrs.Get("kind")
		p.logger.Debug("Kind not found in body, checking attributes",
			zap.Bool("kind_exists_in_attrs", kindExists))
	}
	if !apiVersionExists {
		apiVersionVal, apiVersionExists = attrs.Get("apiVersion")
		p.logger.Debug("apiVersion not found in body, checking attributes",
			zap.Bool("apiVersion_exists_in_attrs", apiVersionExists))
	}

	// Check if this is an OpenReports log
	if !kindExists || kindVal.AsString() != "Report" {
		// Not an OpenReports log, skip
		// Only log at Info level if kind exists but doesn't match (to reduce noise)
		if kindExists && kindVal.AsString() != "Report" {
			p.logger.Info("Log record does not match OpenReports processor - kind field mismatch",
				zap.String("kind_value", kindVal.AsString()),
				zap.String("expected", "Report"),
				zap.String("trace_id", logRecord.TraceID().String()),
				zap.Bool("from_body", body.Type() == pcommon.ValueTypeMap))
		}
		p.logger.Debug("Log record does not match OpenReports processor - kind field check",
			zap.Bool("kind_exists", kindExists),
			zap.String("kind_value", func() string {
				if kindExists {
					return kindVal.AsString()
				}
				return missingValue
			}()),
			zap.String("trace_id", logRecord.TraceID().String()),
			zap.Bool("from_body", body.Type() == pcommon.ValueTypeMap))
		return nil, nil
	}

	if !apiVersionExists || apiVersionVal.AsString() != "openreports.io/v1alpha1" {
		// Not an OpenReports log, skip
		// Only log at Info level if apiVersion exists but doesn't match (to reduce noise)
		if apiVersionExists && apiVersionVal.AsString() != "openreports.io/v1alpha1" {
			p.logger.Info("Log record does not match OpenReports processor - apiVersion mismatch",
				zap.String("apiVersion_value", apiVersionVal.AsString()),
				zap.String("expected", "openreports.io/v1alpha1"),
				zap.String("trace_id", logRecord.TraceID().String()),
				zap.Bool("from_body", body.Type() == pcommon.ValueTypeMap))
		}
		p.logger.Debug("Log record does not match OpenReports processor - apiVersion check",
			zap.Bool("apiVersion_exists", apiVersionExists),
			zap.String("apiVersion_value", func() string {
				if apiVersionExists {
					return apiVersionVal.AsString()
				}
				return missingValue
			}()),
			zap.String("trace_id", logRecord.TraceID().String()),
			zap.Bool("from_body", body.Type() == pcommon.ValueTypeMap))
		return nil, nil
	}

	// Log that we've identified an OpenReports log
	p.logger.Info("OpenReports log identified - processing",
		zap.String("trace_id", logRecord.TraceID().String()),
		zap.String("span_id", logRecord.SpanID().String()),
		zap.String("timestamp", logRecord.Timestamp().String()))
	p.logger.Debug("OpenReports log identified - processing (debug)",
		zap.String("trace_id", logRecord.TraceID().String()),
		zap.String("span_id", logRecord.SpanID().String()),
		zap.String("timestamp", logRecord.Timestamp().String()))

	// Extract data from body Map (k8sobjects receiver format) or attributes (fallback)
	// Helper function to get value from body Map or attributes
	getValue := func(key string) (pcommon.Value, bool) {
		if body.Type() == pcommon.ValueTypeMap {
			if val, ok := bodyMap.Get(key); ok {
				return val, true
			}
		}
		// Fall back to attributes
		return attrs.Get(key)
	}

	// Extract metadata for logging - try body Map first, then attributes
	metadataName, metadataNameExists := getValue("metadata.name")
	if !metadataNameExists && body.Type() == pcommon.ValueTypeMap {
		// Try nested path: metadata.name
		if metadataVal, ok := bodyMap.Get("metadata"); ok && metadataVal.Type() == pcommon.ValueTypeMap {
			metadataName, metadataNameExists = metadataVal.Map().Get("name")
		}
	}

	scopeName, scopeNameExists := getValue("scope.name")
	if !scopeNameExists && body.Type() == pcommon.ValueTypeMap {
		// Try nested path: scope.name
		if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
			scopeName, scopeNameExists = scopeVal.Map().Get("name")
		}
	}

	scopeKind, scopeKindExists := getValue("scope.kind")
	if !scopeKindExists && body.Type() == pcommon.ValueTypeMap {
		// Try nested path: scope.kind
		if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
			scopeKind, scopeKindExists = scopeVal.Map().Get("kind")
		}
	}

	metadataNameStr := ""
	if metadataNameExists {
		metadataNameStr = metadataName.AsString()
	}
	scopeNameStr := ""
	if scopeNameExists {
		scopeNameStr = scopeName.AsString()
	}
	scopeKindStr := ""
	if scopeKindExists {
		scopeKindStr = scopeKind.AsString()
	}

	p.logger.Info("OpenReports log metadata extracted",
		zap.String("metadata.name", metadataNameStr),
		zap.String("scope.name", scopeNameStr),
		zap.String("scope.kind", scopeKindStr),
		zap.Bool("from_body_map", body.Type() == pcommon.ValueTypeMap))
	p.logger.Debug("OpenReports log metadata",
		zap.String("metadata.name", metadataNameStr),
		zap.String("scope.name", scopeNameStr),
		zap.String("scope.kind", scopeKindStr))

	// Extract the results array - try body Map first, then attributes
	resultsVal, exists := getValue("results")
	if !exists && body.Type() == pcommon.ValueTypeMap {
		// Try nested path: results
		resultsVal, exists = bodyMap.Get("results")
	}

	if !exists {
		p.logger.Warn("OpenReports log has no results field",
			zap.String("metadata.name", metadataNameStr),
			zap.String("scope.name", scopeNameStr),
			zap.String("scope.kind", scopeKindStr),
			zap.Bool("body_is_map", body.Type() == pcommon.ValueTypeMap))
		return nil, nil
	}

	p.logger.Debug("Parsing OpenReports results array",
		zap.String("results_type", resultsVal.Type().String()),
		zap.Bool("results_exists", exists))

	// Parse results - k8sobjects receiver stores as slice of Maps, attributes may store as JSON strings
	var resultsArray []string
	if resultsVal.Type() == pcommon.ValueTypeSlice {
		slice := resultsVal.Slice()
		p.logger.Debug("Results is a slice type",
			zap.Int("slice_length", slice.Len()),
			zap.Bool("from_body_map", body.Type() == pcommon.ValueTypeMap))

		// If from body Map, each element is likely a Map that needs to be serialized to JSON
		// If from attributes, each element is likely already a JSON string
		for i := 0; i < slice.Len(); i++ {
			elem := slice.At(i)
			if elem.Type() == pcommon.ValueTypeMap {
				// Serialize Map to JSON string
				resultMap := elem.Map()
				// Convert Map to JSON by building a map[string]interface{} and marshaling
				resultMapJSON := make(map[string]interface{})
				resultMap.Range(func(k string, v pcommon.Value) bool {
					resultMapJSON[k] = valueToInterface(v)
					return true
				})
				resultJSONBytes, err := json.Marshal(resultMapJSON)
				if err != nil {
					p.logger.Warn("Failed to serialize result Map to JSON",
						zap.Int("result_index", i),
						zap.Error(err))
					continue
				}
				resultsArray = append(resultsArray, string(resultJSONBytes))
			} else {
				// Already a string (from attributes)
				resultsArray = append(resultsArray, elem.AsString())
			}
		}
	} else if resultsVal.Type() == pcommon.ValueTypeStr {
		// If it's a single JSON string containing an array, parse it
		resultStr := resultsVal.AsString()
		p.logger.Debug("Results is a string type, attempting JSON parse",
			zap.Int("string_length", len(resultStr)))
		var jsonArray []string
		if err := json.Unmarshal([]byte(resultStr), &jsonArray); err == nil {
			resultsArray = jsonArray
			p.logger.Debug("Successfully parsed JSON array from string",
				zap.Int("array_length", len(resultsArray)))
		} else {
			// Try as single string
			p.logger.Debug("JSON parse failed, treating as single string result",
				zap.Error(err))
			resultsArray = []string{resultStr}
		}
	} else {
		p.logger.Warn("OpenReports log results field has unexpected type",
			zap.String("type", resultsVal.Type().String()),
			zap.String("metadata.name", metadataNameStr),
			zap.Bool("from_body_map", body.Type() == pcommon.ValueTypeMap))
		return nil, nil
	}

	p.logger.Info("Parsed results array from OpenReports log",
		zap.Int("total_results", len(resultsArray)),
		zap.String("metadata.name", metadataNameStr),
		zap.String("scope.name", scopeNameStr),
		zap.String("scope.kind", scopeKindStr))
	p.logger.Debug("Parsed results array",
		zap.Int("total_results", len(resultsArray)))

	if len(resultsArray) == 0 {
		p.logger.Info("OpenReports log has empty results array - skipping",
			zap.String("metadata.name", metadataNameStr),
			zap.String("scope.name", scopeNameStr))
		p.logger.Debug("OpenReports log has empty results array",
			zap.String("metadata.name", metadataNameStr))
		return nil, nil
	}

	// Extract remaining metadata from body Map or attributes
	metadataNamespaceVal, metadataNamespaceExists := getValue("metadata.namespace")
	if !metadataNamespaceExists && body.Type() == pcommon.ValueTypeMap {
		if metadataVal, ok := bodyMap.Get("metadata"); ok && metadataVal.Type() == pcommon.ValueTypeMap {
			metadataNamespaceVal, metadataNamespaceExists = metadataVal.Map().Get("namespace")
		}
	}

	scopeNamespaceVal, scopeNamespaceExists := getValue("scope.namespace")
	if !scopeNamespaceExists && body.Type() == pcommon.ValueTypeMap {
		if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
			scopeNamespaceVal, scopeNamespaceExists = scopeVal.Map().Get("namespace")
		}
	}

	scopeUIDVal, scopeUIDExists := getValue("scope.uid")
	if !scopeUIDExists && body.Type() == pcommon.ValueTypeMap {
		if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
			scopeUIDVal, scopeUIDExists = scopeVal.Map().Get("uid")
		}
	}

	scopeAPIVersionVal, scopeAPIVersionExists := getValue("scope.apiVersion")
	if !scopeAPIVersionExists && body.Type() == pcommon.ValueTypeMap {
		if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
			scopeAPIVersionVal, scopeAPIVersionExists = scopeVal.Map().Get("apiVersion")
		}
	}

	timestamp := logRecord.Timestamp()

	metadataNamespaceStr := ""
	if metadataNamespaceExists {
		metadataNamespaceStr = metadataNamespaceVal.AsString()
	}
	scopeNamespaceStr := ""
	if scopeNamespaceExists {
		scopeNamespaceStr = scopeNamespaceVal.AsString()
	}
	scopeUIDStr := ""
	if scopeUIDExists {
		scopeUIDStr = scopeUIDVal.AsString()
	}
	scopeAPIVersionStr := ""
	if scopeAPIVersionExists {
		scopeAPIVersionStr = scopeAPIVersionVal.AsString()
	}

	// Extract workload information from owner references
	// Check body Map first, then attributes
	var workloadAttrs pcommon.Map
	if body.Type() == pcommon.ValueTypeMap {
		if metadataVal, ok := bodyMap.Get("metadata"); ok && metadataVal.Type() == pcommon.ValueTypeMap {
			workloadAttrs = metadataVal.Map()
		} else {
			workloadAttrs = attrs
		}
	} else {
		workloadAttrs = attrs
	}

	p.logger.Debug("Extracting workload information",
		zap.String("scope.name", scopeNameStr),
		zap.String("scope.namespace", scopeNamespaceStr),
		zap.Bool("from_body_map", body.Type() == pcommon.ValueTypeMap))
	workloadInfo := extractWorkloadInfo(workloadAttrs, scopeNameStr, scopeNamespaceStr)

	if workloadInfo.name != "" {
		p.logger.Debug("Workload information extracted",
			zap.String("workload.name", workloadInfo.name),
			zap.String("workload.kind", workloadInfo.kind),
			zap.String("workload.namespace", workloadInfo.namespace),
			zap.String("workload.uid", workloadInfo.uid))
	} else {
		p.logger.Debug("No workload information found - will infer from pod name if applicable")
	}

	// Get pod identifier for tracking processed results
	podIdentifier := p.getPodIdentifier(scopeUIDStr, scopeNameStr, scopeNamespaceStr)

	// Log status filter configuration
	if len(p.config.StatusFilter) > 0 {
		p.logger.Debug("Status filter active",
			zap.Strings("allowed_statuses", p.config.StatusFilter),
			zap.Int("total_results", len(resultsArray)))
	} else {
		p.logger.Debug("No status filter configured - processing all results",
			zap.Int("total_results", len(resultsArray)))
	}

	// Check if this is the first time we're seeing results for this pod
	p.mu.RLock()
	firstTime := p.processedResults[podIdentifier] == nil
	p.mu.RUnlock()

	// Determine which results to process
	// First time: process all results
	// Subsequent times: only process the latest (last) result
	var resultsToProcess []int
	if firstTime {
		p.logger.Debug("First time processing results for pod - will process all results",
			zap.String("pod_identifier", podIdentifier),
			zap.Int("total_results", len(resultsArray)))
		// Process all results
		for i := 0; i < len(resultsArray); i++ {
			resultsToProcess = append(resultsToProcess, i)
		}
	} else {
		p.mu.RLock()
		processedCount := len(p.processedResults[podIdentifier])
		p.mu.RUnlock()
		// Only process the last (latest) result
		if len(resultsArray) > 0 {
			resultsToProcess = append(resultsToProcess, len(resultsArray)-1)
			p.logger.Debug("Subsequent processing for pod - will only process latest result",
				zap.String("pod_identifier", podIdentifier),
				zap.Int("total_results", len(resultsArray)),
				zap.Int("previously_processed", processedCount),
				zap.Int("latest_result_index", len(resultsArray)-1))
		}
	}

	// Create a new log record for each result
	var newRecords []plog.LogRecord
	processedCount := 0
	filteredCount := 0
	duplicateCount := 0

	for _, i := range resultsToProcess {
		resultJSONStr := resultsArray[i]

		p.logger.Debug("Parsing result",
			zap.Int("result_index", i),
			zap.Int("result_length", len(resultJSONStr)))

		// Parse the result JSON
		var result Result
		if err := json.Unmarshal([]byte(resultJSONStr), &result); err != nil {
			p.logger.Warn("Failed to parse result JSON",
				zap.Int("result_index", i),
				zap.String("result_preview", func() string {
					if len(resultJSONStr) > 200 {
						return resultJSONStr[:200] + "..."
					}
					return resultJSONStr
				}()),
				zap.Error(err))
			continue
		}

		p.logger.Debug("Parsed result successfully",
			zap.Int("result_index", i),
			zap.String("policy", result.Policy),
			zap.String("rule", result.Rule),
			zap.String("result", result.Result),
			zap.String("source", result.Source))

		// Generate unique identifier for this result
		resultID := p.generateResultID(resultJSONStr)

		// Check if this result has already been processed
		p.mu.RLock()
		alreadyProcessed := p.processedResults[podIdentifier] != nil && p.processedResults[podIdentifier][resultID]
		p.mu.RUnlock()

		if alreadyProcessed {
			p.logger.Debug("Skipping already processed result",
				zap.Int("result_index", i),
				zap.String("result_id", resultID),
				zap.String("policy", result.Policy),
				zap.String("rule", result.Rule))
			duplicateCount++
			continue
		}

		// Filter by status if configured
		if len(p.config.StatusFilter) > 0 {
			if !p.isStatusAllowed(result.Result) {
				p.logger.Info("Skipping result due to status filter",
					zap.Int("result_index", i),
					zap.String("status", result.Result),
					zap.String("policy", result.Policy),
					zap.String("rule", result.Rule),
					zap.Strings("allowed_statuses", p.config.StatusFilter),
					zap.String("metadata.name", metadataNameStr))
				p.logger.Debug("Skipping result due to status filter",
					zap.Int("result_index", i),
					zap.String("status", result.Result),
					zap.String("policy", result.Policy),
					zap.String("rule", result.Rule),
					zap.Strings("allowed_statuses", p.config.StatusFilter))
				filteredCount++
				continue
			}
		}

		p.logger.Info("Result passed status filter, creating security event",
			zap.Int("result_index", i),
			zap.String("status", result.Result),
			zap.String("policy", result.Policy),
			zap.String("rule", result.Rule),
			zap.String("metadata.name", metadataNameStr),
			zap.String("scope.name", scopeNameStr))
		p.logger.Debug("Result passed status filter, creating security event",
			zap.Int("result_index", i),
			zap.String("status", result.Result),
			zap.String("policy", result.Policy),
			zap.String("rule", result.Rule))

		// Create a new log record for this result
		newRecord := plog.NewLogRecord()

		// Copy basic fields from original
		newRecord.SetTimestamp(timestamp)
		newRecord.SetObservedTimestamp(logRecord.ObservedTimestamp())
		// Note: severity_number and severity_text are set in transformToSecurityEvent
		// based on finding.severity to maintain OpenTelemetry log schema compliance
		newRecord.SetTraceID(logRecord.TraceID())
		newRecord.SetSpanID(logRecord.SpanID())
		newRecord.SetFlags(logRecord.Flags())

		// Get original severity from the OpenReports result (not from OpenTelemetry log)
		originalSeverity := result.Severity

		// Extract k8s attributes from original log for enriching original_content
		// Check both attributes and body Map (for k8sobjects receiver)
		var bodyMapForExtraction *pcommon.Map
		if body.Type() == pcommon.ValueTypeMap {
			bodyMap := body.Map()
			bodyMapForExtraction = &bodyMap
		}
		k8sAttrs := extractK8sAttributesForOriginalContent(attrs, bodyMapForExtraction)

		// Transform the result into a security event
		p.transformToSecurityEvent(&newRecord, result, resultJSONStr, originalSeverity, k8sAttrs, map[string]interface{}{
			"metadata.name":      metadataNameStr,
			"metadata.namespace": metadataNamespaceStr,
			"scope.name":         scopeNameStr,
			"scope.namespace":    scopeNamespaceStr,
			"scope.kind":         scopeKindStr,
			"scope.uid":          scopeUIDStr,
			"scope.apiVersion":   scopeAPIVersionStr,
			"workload.name":      workloadInfo.name,
			"workload.kind":      workloadInfo.kind,
			"workload.namespace": workloadInfo.namespace,
			"workload.uid":       workloadInfo.uid,
		}, attrs)

		newRecords = append(newRecords, newRecord)
		processedCount++

		p.logger.Info("Security event created successfully",
			zap.Int("result_index", i),
			zap.String("policy", result.Policy),
			zap.String("rule", result.Rule),
			zap.String("status", result.Result),
			zap.String("metadata.name", metadataNameStr),
			zap.String("scope.name", scopeNameStr),
			zap.Int("total_events_created", len(newRecords)))

		// Mark this result as processed
		p.mu.Lock()
		if p.processedResults[podIdentifier] == nil {
			p.processedResults[podIdentifier] = make(map[string]bool)
		}
		p.processedResults[podIdentifier][resultID] = true
		p.mu.Unlock()
	}

	p.logger.Info("OpenReports log processing completed",
		zap.Int("original_logs", 1),
		zap.Int("total_results", len(resultsArray)),
		zap.Int("processed_results", processedCount),
		zap.Int("filtered_results", filteredCount),
		zap.Int("duplicate_results", duplicateCount),
		zap.Int("security_events_created", len(newRecords)),
		zap.String("metadata.name", metadataNameStr),
		zap.String("scope.name", scopeNameStr),
		zap.Bool("first_time", firstTime))

	p.logger.Debug("OpenReports log transformation summary",
		zap.Int("original_logs", 1),
		zap.Int("total_results", len(resultsArray)),
		zap.Int("processed_results", processedCount),
		zap.Int("filtered_results", filteredCount),
		zap.Int("duplicate_results", duplicateCount),
		zap.Int("security_events_created", len(newRecords)),
		zap.Bool("status_filter_enabled", len(p.config.StatusFilter) > 0),
		zap.Bool("first_time", firstTime),
		zap.String("metadata.name", metadataNameStr))

	return newRecords, nil
}

// getPodIdentifier generates a unique identifier for a pod/workload
// Uses scope.uid if available, otherwise falls back to scope.name+scope.namespace
func (p *Processor) getPodIdentifier(scopeUID, scopeName, scopeNamespace string) string {
	if scopeUID != "" {
		return scopeUID
	}
	if scopeName != "" && scopeNamespace != "" {
		return fmt.Sprintf("%s/%s", scopeNamespace, scopeName)
	}
	if scopeName != "" {
		return scopeName
	}
	return "unknown"
}

// generateResultID generates a unique identifier for a result
// Uses SHA256 hash of the result JSON string to ensure uniqueness
func (p *Processor) generateResultID(resultJSON string) string {
	hash := sha256.Sum256([]byte(resultJSON))
	return hex.EncodeToString(hash[:])
}

// Result represents a single result from the OpenReports results array
type Result struct {
	Source     string                 `json:"source"`
	Timestamp  Timestamp              `json:"timestamp"`
	Message    string                 `json:"message"`
	Policy     string                 `json:"policy"`
	Properties map[string]interface{} `json:"properties"`
	Result     string                 `json:"result"` // pass, fail, error, skip
	Rule       string                 `json:"rule"`
	Scored     bool                   `json:"scored"`
	Severity   string                 `json:"severity,omitempty"`
	Category   string                 `json:"category,omitempty"`
}

// Timestamp represents the timestamp in the result
type Timestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int64 `json:"nanos"`
}

// transformToSecurityEvent transforms a result into a security event log record
//
//nolint:gocyclo // Complex field mapping with multiple conditional branches for schema transformation
func (p *Processor) transformToSecurityEvent(logRecord *plog.LogRecord, result Result, originalContent string, originalSeverity string, k8sAttrs map[string]interface{}, metadata map[string]interface{}, originalAttrs pcommon.Map) {
	attrs := logRecord.Attributes()

	// Generate event ID
	eventID := uuid.New().String()
	attrs.PutStr("event.id", eventID)

	// Hardcoded event fields
	attrs.PutStr("event.version", "1.309")
	attrs.PutStr("event.category", "COMPLIANCE")
	attrs.PutStr("event.name", "Compliance finding event")
	attrs.PutStr("event.type", "COMPLIANCE_FINDING")

	// Event description: "Policy violation on <pod> for rule <rule>" or appropriate message based on result
	scopeName := getString(metadata, "scope.name")
	rule := result.Rule
	if rule == "" {
		rule = "unknown"
	}

	var eventDescription string
	switch result.Result {
	case resultStatusFail:
		eventDescription = fmt.Sprintf("Policy violation on %s for rule %s", scopeName, rule)
	case resultStatusPass:
		eventDescription = fmt.Sprintf("Policy check passed on %s for rule %s", scopeName, rule)
	case resultStatusError:
		eventDescription = fmt.Sprintf("Policy check error on %s for rule %s", scopeName, rule)
	case resultStatusSkip:
		eventDescription = fmt.Sprintf("Policy check skipped on %s for rule %s", scopeName, rule)
	default:
		eventDescription = fmt.Sprintf("Policy evaluation on %s for rule %s", scopeName, rule)
	}
	attrs.PutStr("event.description", eventDescription)

	// Product fields - vendor comes from result.Source (e.g., "kyverno")
	productVendor := result.Source
	if productVendor == "" {
		productVendor = "unknown"
	}
	attrs.PutStr("product.vendor", productVendor)
	attrs.PutStr("product.name", productVendor)

	// Event provider equals product vendor
	attrs.PutStr("event.provider", productVendor)

	// Store original content enriched with k8s attributes
	if originalContent != "" {
		enrichedContent := enrichOriginalContentWithK8sAttrs(originalContent, k8sAttrs)
		attrs.PutStr("event.original_content", enrichedContent)
	}

	// Smartscape type - K8S_POD if scope.kind is Pod
	scopeKind := getString(metadata, "scope.kind")
	if scopeKind == k8sKindPod {
		attrs.PutStr("smartscape.type", "K8S_POD")
	}

	// Calculate risk score based on severity (for dt.security.risk.score)
	riskScore := calculateRiskScoreFromSeverity(result.Severity)
	attrs.PutDouble("dt.security.risk.score", riskScore)

	// Object fields
	scopeUID := getString(metadata, "scope.uid")
	if scopeUID != "" {
		attrs.PutStr("object.id", scopeUID)
	}
	if scopeKind != "" {
		attrs.PutStr("object.type", scopeKind)

		// Add corresponding k8s object field based on object.type
		if scopeUID != "" {
			switch scopeKind {
			case "Namespace":
				attrs.PutStr("k8s.namespace.uid", scopeUID)
			case "Pod":
				attrs.PutStr("k8s.pod.uid", scopeUID)
			case "Job", "DaemonSet", "Deployment", "StatefulSet", "ReplicaSet":
				// For workload types, use k8s.workload.uid
				attrs.PutStr("k8s.workload.uid", scopeUID)
			}
		}
	}
	// Note: object.name will be set after copyK8sFields to ensure it's not overwritten

	// Finding fields
	// Note: finding.description removed (was result.Message) per requirements
	findingID := uuid.New().String()
	attrs.PutStr("finding.id", findingID)

	// Save original status in finding.status
	attrs.PutStr("finding.status", result.Result)

	// finding.severity should use the original value from the OpenReports result (not uppercase)
	// But we still need uppercase for LogRecord severity fields for OpenTelemetry compliance
	var severityText string
	if result.Severity != "" {
		// Store finding.severity as original value from result
		attrs.PutStr("finding.severity", result.Severity)
		// Use uppercase version for LogRecord severity fields
		severityText = mapSeverityToUppercase(result.Severity)
	} else {
		// Default to MEDIUM if no severity provided
		attrs.PutStr("finding.severity", riskLevelMedium)
		severityText = riskLevelMedium
	}

	// Set LogRecord severity fields to maintain OpenTelemetry log schema compliance
	// Required for proper log record structure even though severity is also in finding.severity attribute
	logRecord.SetSeverityNumber(mapSeverityToSeverityNumber(severityText))
	logRecord.SetSeverityText(severityText)

	// Finding time.created from result timestamp
	if result.Timestamp.Seconds > 0 {
		resultTime := time.Unix(result.Timestamp.Seconds, result.Timestamp.Nanos)
		logRecord.SetTimestamp(pcommon.NewTimestampFromTime(resultTime))
		// Also store as finding.time.created
		attrs.PutStr("finding.time.created", resultTime.Format(time.RFC3339Nano))
	}

	// Finding title: policy + rule
	findingTitle := result.Policy
	if result.Rule != "" {
		findingTitle = fmt.Sprintf("%s - %s", result.Policy, result.Rule)
	}
	attrs.PutStr("finding.title", findingTitle)

	// Finding type is the policy
	if result.Policy != "" {
		attrs.PutStr("finding.type", result.Policy)
	}

	// Finding URL - only add if not null or empty
	// Note: Currently result doesn't have a URL field, so we check if it exists in properties
	if result.Properties != nil {
		if urlVal, ok := result.Properties["url"]; ok {
			if urlStr, ok := urlVal.(string); ok && urlStr != "" {
				attrs.PutStr("finding.url", urlStr)
			}
		}
	}

	// Compliance fields
	if result.Rule != "" {
		attrs.PutStr("compliance.control", result.Rule)
	}
	if result.Policy != "" {
		attrs.PutStr("compliance.requirements", result.Policy)
	}
	// compliance.standards can be omitted or hardcoded
	// For now, we'll omit it or use category if available
	if result.Category != "" {
		attrs.PutStr("compliance.standards", result.Category)
	}

	// Map result.result to compliance.status (normalized: FAILED, PASSED, NOT_RELEVANT)
	complianceStatus := normalizeComplianceStatus(result.Result)
	attrs.PutStr("compliance.status", complianceStatus)

	// Copy all k8s.* fields from original log
	copyK8sFields(attrs, originalAttrs, metadata)

	// Remove unwanted fields that might have been copied from original log
	// These fields come from the initial OpenTelemetry log that the processor is handling
	attrs.Remove("severity")
	attrs.Remove("message")
	attrs.Remove("severity_number")
	attrs.Remove("source")

	// Remove redundant k8s fields (we have k8s.namespace.name and k8s.deployment.name/etc instead)
	attrs.Remove("k8s.resource.name")
	attrs.Remove("k8s.workload.namespace")

	// Ensure object.name is set to the k8s resource name (scope.name)
	// This should be the resource affected by the kyverno rule
	if scopeName != "" {
		attrs.PutStr("object.name", scopeName)
	} else {
		// Fallback: try to get from metadata if scopeName is empty
		if name, ok := metadata["scope.name"]; ok {
			attrs.PutStr("object.name", fmt.Sprintf("%v", name))
		}
	}

	// Set log body to event description to ensure logs are not rejected as empty
	// Dynatrace may require a non-empty body even though OpenTelemetry spec allows empty body
	logRecord.Body().SetStr(eventDescription)
}

// mapSeverityToUppercase maps finding severity to uppercase format
func mapSeverityToUppercase(severity string) string {
	switch severity {
	case "critical":
		return riskLevelCritical
	case "high":
		return riskLevelHigh
	case "medium":
		return riskLevelMedium
	case "low":
		return riskLevelLow
	default:
		// Return as-is if unknown, or default to MEDIUM
		return riskLevelMedium
	}
}

// mapSeverityToSeverityNumber maps severity text to OpenTelemetry SeverityNumber
// Required to maintain OpenTelemetry log schema compliance
// Severity numbers: TRACE=1-4, DEBUG=5-8, INFO=9-12, WARN=13-16, ERROR=17-20, FATAL=21-24
func mapSeverityToSeverityNumber(severityText string) plog.SeverityNumber {
	switch severityText {
	case riskLevelCritical:
		return plog.SeverityNumberFatal // 21-24, use FATAL for critical
	case riskLevelHigh:
		return plog.SeverityNumberError // 17-20, use ERROR for high
	case riskLevelMedium:
		return plog.SeverityNumberWarn // 13-16, use WARN for medium
	case riskLevelLow:
		return plog.SeverityNumberInfo // 9-12, use INFO for low
	default:
		return plog.SeverityNumberWarn // Default to WARN for unknown
	}
}

// calculateRiskScoreFromSeverity calculates the risk score based on finding severity
func calculateRiskScoreFromSeverity(severity string) float64 {
	switch severity {
	case "critical":
		return 10.0
	case "high":
		return 8.9
	case "medium":
		return 6.9
	case "low":
		return 3.9
	default:
		return 0.0
	}
}

// normalizeComplianceStatus maps result.result to normalized compliance.status
// Returns FAILED, PASSED, or NOT_RELEVANT
func normalizeComplianceStatus(result string) string {
	switch result {
	case resultStatusPass:
		return "PASSED"
	case resultStatusFail:
		return "FAILED"
	case resultStatusError, resultStatusSkip:
		return "NOT_RELEVANT"
	default:
		return "NOT_RELEVANT" // default for unknown statuses
	}
}

// valueToInterface converts a pcommon.Value to interface{} for JSON marshaling
func valueToInterface(v pcommon.Value) interface{} {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return v.AsString()
	case pcommon.ValueTypeInt:
		return v.Int()
	case pcommon.ValueTypeDouble:
		return v.Double()
	case pcommon.ValueTypeBool:
		return v.Bool()
	case pcommon.ValueTypeMap:
		result := make(map[string]interface{})
		v.Map().Range(func(k string, val pcommon.Value) bool {
			result[k] = valueToInterface(val)
			return true
		})
		return result
	case pcommon.ValueTypeSlice:
		var result []interface{}
		slice := v.Slice()
		for i := 0; i < slice.Len(); i++ {
			result = append(result, valueToInterface(slice.At(i)))
		}
		return result
	default:
		return v.AsString() // fallback to string representation
	}
}

// workloadInfo represents extracted workload information
type workloadInfo struct {
	name      string
	kind      string
	namespace string
	uid       string
}

// extractWorkloadInfo extracts workload information from owner references or pod name
//
//nolint:gocyclo // Complex workload extraction logic with multiple nested conditionals for K8s metadata parsing
func extractWorkloadInfo(attrs pcommon.Map, podName string, namespace string) workloadInfo {
	info := workloadInfo{}
	info.namespace = namespace // Workload namespace is the same as pod namespace

	// Try to extract from owner references first
	ownerRefsVal, exists := attrs.Get("metadata.ownerReferences")
	if exists {
		// ownerReferences is stored as an array of JSON strings
		var ownerRefs []string
		if ownerRefsVal.Type() == pcommon.ValueTypeSlice {
			slice := ownerRefsVal.Slice()
			for i := 0; i < slice.Len(); i++ {
				ownerRefs = append(ownerRefs, slice.At(i).AsString())
			}
		} else if ownerRefsVal.Type() == pcommon.ValueTypeStr {
			var jsonArray []string
			if err := json.Unmarshal([]byte(ownerRefsVal.AsString()), &jsonArray); err == nil {
				ownerRefs = jsonArray
			} else {
				ownerRefs = []string{ownerRefsVal.AsString()}
			}
		}

		// Parse owner references to find workload
		for _, ownerRefStr := range ownerRefs {
			var ownerRef map[string]interface{}
			if err := json.Unmarshal([]byte(ownerRefStr), &ownerRef); err == nil {
				kind, ok := ownerRef["kind"].(string)
				if ok && isWorkloadKind(kind) {
					info.kind = kind
					if name, ok := ownerRef["name"].(string); ok {
						info.name = name
					}
					if uid, ok := ownerRef["uid"].(string); ok {
						info.uid = uid
					}
					break // Take the first workload owner
				}
			}
		}
	}

	// If we couldn't find workload from owner references, try to infer from pod name
	if info.name == "" && podName != "" {
		// Pod names typically follow pattern: <workload-name>-<hash>-<random>
		// e.g., "cert-manager-cainjector-89fd4b8f9-t9xlf" -> "cert-manager-cainjector"
		// Extract workload name by removing hash and random suffix
		parts := splitPodName(podName)
		if len(parts) >= 2 {
			// Remove the last two parts (hash and random)
			workloadName := ""
			for i := 0; i < len(parts)-2; i++ {
				if i > 0 {
					workloadName += "-"
				}
				workloadName += parts[i]
			}
			if workloadName != "" {
				info.name = workloadName
				// Default to Deployment if kind is not known
				if info.kind == "" {
					info.kind = k8sKindDeployment
				}
			}
		}
	}

	return info
}

// isWorkloadKind checks if a Kubernetes kind is a workload type
func isWorkloadKind(kind string) bool {
	workloadKinds := map[string]bool{
		k8sKindDeployment: true,
		"StatefulSet":     true,
		"DaemonSet":       true,
		"Job":             true,
		"CronJob":         true,
		"ReplicaSet":      true,
	}
	return workloadKinds[kind]
}

// splitPodName splits a pod name into its components
func splitPodName(podName string) []string {
	var parts []string
	current := ""
	for _, char := range podName {
		if char == '-' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// copyK8sFields copies all k8s.* fields from the original attributes
//
//nolint:gocyclo // Complex field copying with multiple conditional branches for K8s attribute mapping
func copyK8sFields(targetAttrs pcommon.Map, originalAttrs pcommon.Map, metadata map[string]interface{}) {
	// Copy k8s.* fields from original attributes, but exclude unwanted fields
	originalAttrs.Range(func(key string, value pcommon.Value) bool {
		if len(key) > 4 && key[:4] == "k8s." {
			// Skip k8s.resource.uid as we'll set it based on kind
			// Skip k8s.resource.name and k8s.workload.namespace as they are redundant
			// (we have k8s.namespace.name and k8s.deployment.name/statefulset.name/etc instead)
			if key != "k8s.resource.uid" && key != "k8s.resource.kind" &&
				key != "k8s.resource.name" && key != "k8s.workload.namespace" {
				copyValue(targetAttrs, key, value)
			}
		}
		return true
	})

	// Also add k8s fields from metadata if available
	// Only set k8s.pod.name for actual Pod objects, not for workloads
	if scopeNamespace, ok := metadata["scope.namespace"]; ok {
		targetAttrs.PutStr("k8s.namespace.name", fmt.Sprintf("%v", scopeNamespace))
	}
	if scopeKind, ok := metadata["scope.kind"]; ok {
		kindStr := fmt.Sprintf("%v", scopeKind)
		// Note: k8s.resource.kind removed per requirements
		// Only set k8s.pod.name for actual Pod objects
		if kindStr == k8sKindPod {
			if scopeName, ok := metadata["scope.name"]; ok {
				targetAttrs.PutStr("k8s.pod.name", fmt.Sprintf("%v", scopeName))
			}
		}
		// Set k8s.resource.uid to the appropriate field based on kind
		if scopeUID, ok := metadata["scope.uid"]; ok {
			uidStr := fmt.Sprintf("%v", scopeUID)
			// Map k8s.resource.uid to the correct field based on kind
			switch kindStr {
			case k8sKindPod:
				targetAttrs.PutStr("k8s.pod.uid", uidStr)
			case "Namespace":
				targetAttrs.PutStr("k8s.namespace.uid", uidStr)
			case "Job", "DaemonSet", "Deployment", "StatefulSet", "ReplicaSet":
				// For workload types, use k8s.workload.uid
				targetAttrs.PutStr("k8s.workload.uid", uidStr)
			case "CronJob":
				targetAttrs.PutStr("k8s.cronjob.uid", uidStr)
			default:
				// For unknown kinds, use generic k8s.resource.uid
				targetAttrs.PutStr("k8s.resource.uid", uidStr)
			}
		}
	} else {
		// If no scope.kind, still set k8s.resource.uid if available
		if scopeUID, ok := metadata["scope.uid"]; ok {
			targetAttrs.PutStr("k8s.resource.uid", fmt.Sprintf("%v", scopeUID))
		}
	}

	// Add workload fields from workload.* metadata (if available)
	if workloadName, ok := metadata["workload.name"]; ok && workloadName != "" {
		workloadKind := getString(metadata, "workload.kind")
		switch workloadKind {
		case k8sKindDeployment:
			targetAttrs.PutStr("k8s.deployment.name", fmt.Sprintf("%v", workloadName))
		case "StatefulSet":
			targetAttrs.PutStr("k8s.statefulset.name", fmt.Sprintf("%v", workloadName))
		case "DaemonSet":
			targetAttrs.PutStr("k8s.daemonset.name", fmt.Sprintf("%v", workloadName))
		}
		targetAttrs.PutStr("k8s.workload.name", fmt.Sprintf("%v", workloadName))
		targetAttrs.PutStr("k8s.workload.kind", workloadKind)
	}
	// k8s.workload.namespace removed - use k8s.namespace.name instead (already set above from scope.namespace)
	if workloadUID, ok := metadata["workload.uid"]; ok && workloadUID != "" {
		targetAttrs.PutStr("k8s.workload.uid", fmt.Sprintf("%v", workloadUID))
	}

	// Add k8s.*.name fields based on scope.kind and scope.name (for OpenReports CRs)
	// This ensures that when object.type is StatefulSet, Deployment, etc., we have the corresponding k8s.*.name field
	if scopeKind, ok := metadata["scope.kind"]; ok {
		kindStr := fmt.Sprintf("%v", scopeKind)
		if scopeName, ok := metadata["scope.name"]; ok && scopeName != "" {
			nameStr := fmt.Sprintf("%v", scopeName)
			switch kindStr {
			case "StatefulSet":
				// Only set if not already set from workload.name
				if _, exists := targetAttrs.Get("k8s.statefulset.name"); !exists {
					targetAttrs.PutStr("k8s.statefulset.name", nameStr)
				}
			case "Deployment":
				// Only set if not already set from workload.name
				if _, exists := targetAttrs.Get("k8s.deployment.name"); !exists {
					targetAttrs.PutStr("k8s.deployment.name", nameStr)
				}
			case "DaemonSet":
				// Only set if not already set from workload.name
				if _, exists := targetAttrs.Get("k8s.daemonset.name"); !exists {
					targetAttrs.PutStr("k8s.daemonset.name", nameStr)
				}
			case "Job":
				// Set k8s.job.name for Job objects
				if _, exists := targetAttrs.Get("k8s.job.name"); !exists {
					targetAttrs.PutStr("k8s.job.name", nameStr)
				}
			case "CronJob":
				// Set k8s.cronjob.name for CronJob objects
				if _, exists := targetAttrs.Get("k8s.cronjob.name"); !exists {
					targetAttrs.PutStr("k8s.cronjob.name", nameStr)
				}
			}
		}
	}
}

// copyValue copies a pcommon.Value to the target map
func copyValue(target pcommon.Map, key string, value pcommon.Value) {
	switch value.Type() {
	case pcommon.ValueTypeStr:
		target.PutStr(key, value.Str())
	case pcommon.ValueTypeInt:
		target.PutInt(key, value.Int())
	case pcommon.ValueTypeDouble:
		target.PutDouble(key, value.Double())
	case pcommon.ValueTypeBool:
		target.PutBool(key, value.Bool())
	case pcommon.ValueTypeSlice:
		slice := target.PutEmptySlice(key)
		value.Slice().CopyTo(slice)
	case pcommon.ValueTypeMap:
		m := target.PutEmptyMap(key)
		value.Map().CopyTo(m)
	}
}

// extractK8sAttributesForOriginalContent extracts k8s attributes and metadata from original log for enriching original_content
// Checks both attributes and body Map (for k8sobjects receiver)
func extractK8sAttributesForOriginalContent(originalAttrs pcommon.Map, bodyMap *pcommon.Map) map[string]interface{} {
	k8sAttrs := make(map[string]interface{})

	// Helper to get value from body Map or attributes
	getValueForEnrichment := func(key string) (pcommon.Value, bool) {
		// First try body Map (k8sobjects receiver format)
		if bodyMap != nil {
			// Try direct key
			if val, ok := bodyMap.Get(key); ok {
				return val, true
			}
			// Try nested paths for metadata and scope
			if key == "metadata.name" || key == "metadata.namespace" || key == "metadata.creationTimestamp" ||
				key == "metadata.generation" || key == "metadata.resourceVersion" || key == "metadata.uid" ||
				key == "metadata.labels" || key == "metadata.ownerReferences" || key == "metadata.managedFields" {
				if metadataVal, ok := bodyMap.Get("metadata"); ok && metadataVal.Type() == pcommon.ValueTypeMap {
					fieldName := key[9:] // Remove "metadata." prefix
					if val, ok := metadataVal.Map().Get(fieldName); ok {
						return val, true
					}
				}
			}
			if key == "scope.name" || key == "scope.namespace" || key == "scope.kind" || key == "scope.uid" ||
				key == "scope.apiVersion" {
				if scopeVal, ok := bodyMap.Get("scope"); ok && scopeVal.Type() == pcommon.ValueTypeMap {
					fieldName := key[6:] // Remove "scope." prefix
					if val, ok := scopeVal.Map().Get(fieldName); ok {
						return val, true
					}
				}
			}
		}
		// Fall back to attributes
		return originalAttrs.Get(key)
	}

	// Extract k8s.* attributes (these are always in attributes, added by processors)
	originalAttrs.Range(func(key string, value pcommon.Value) bool {
		if len(key) > 4 && key[:4] == "k8s." {
			k8sAttrs[key] = valueToInterface(value)
		}
		return true
	})

	// Extract metadata, scope, and other fields (check both body Map and attributes)
	fieldsToExtract := []string{
		"metadata.name", "metadata.namespace", "metadata.creationTimestamp",
		"metadata.generation", "metadata.resourceVersion", "metadata.uid",
		"metadata.labels", "metadata.ownerReferences", "metadata.managedFields",
		"scope.name", "scope.namespace", "scope.kind", "scope.uid", "scope.apiVersion",
		"source", "summary.error", "summary.fail", "summary.pass", "summary.skip", "summary.warn",
		"kind", "apiVersion",
	}

	for _, key := range fieldsToExtract {
		if val, ok := getValueForEnrichment(key); ok {
			k8sAttrs[key] = valueToInterface(val)
		}
	}

	return k8sAttrs
}

// enrichOriginalContentWithK8sAttrs creates a JSON object that includes both the result JSON and k8s metadata
// The result object fields are merged at the top level with k8s attributes
func enrichOriginalContentWithK8sAttrs(resultJSON string, k8sAttrs map[string]interface{}) string {
	// Parse the result JSON
	var resultObj map[string]interface{}
	if err := json.Unmarshal([]byte(resultJSON), &resultObj); err != nil {
		// If parsing fails, return original content with k8s attrs as a new object
		enriched := map[string]interface{}{
			"result": resultJSON,
		}
		// Add k8s attributes at the top level
		for k, v := range k8sAttrs {
			enriched[k] = v
		}
		if enrichedJSON, err := json.Marshal(enriched); err == nil {
			return string(enrichedJSON)
		}
		return resultJSON
	}

	// Start with the result object fields
	enriched := make(map[string]interface{})
	for k, v := range resultObj {
		enriched[k] = v
	}

	// Add k8s attributes at the top level (will override result fields if there are conflicts)
	for k, v := range k8sAttrs {
		enriched[k] = v
	}

	// Marshal to JSON
	enrichedJSON, err := json.Marshal(enriched)
	if err != nil {
		// Fallback to original content if marshaling fails
		return resultJSON
	}

	return string(enrichedJSON)
}

// getString safely gets a string value from metadata
func getString(metadata map[string]interface{}, key string) string {
	if val, ok := metadata[key]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// isStatusAllowed checks if a result status is in the allowed filter list
func (p *Processor) isStatusAllowed(status string) bool {
	// If no filter is configured, allow all statuses
	if len(p.config.StatusFilter) == 0 {
		return true
	}

	// Check if status is in the filter list
	for _, allowedStatus := range p.config.StatusFilter {
		if status == allowedStatus {
			return true
		}
	}

	return false
}
