package openreports

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

func TestProcessLogRecord_NotOpenReportsLog(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "NotReport")
	attrs.PutStr("apiVersion", "v1")

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	assert.Nil(t, records, "Should return nil for non-OpenReports logs")
}

func TestProcessLogRecord_OpenReportsLog_NoResults(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	// No results field

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	assert.Nil(t, records, "Should return nil when no results")
}

func TestProcessLogRecord_OpenReportsLog_EmptyResults(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	resultsSlice := attrs.PutEmptySlice("results")
	// Empty slice

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	assert.Nil(t, records, "Should return nil when results are empty")
	_ = resultsSlice // Suppress unused warning
}

func TestProcessLogRecord_OpenReportsLog_SingleResult(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("metadata.name", "test-report")
	attrs.PutStr("metadata.namespace", "test-namespace")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")
	attrs.PutStr("scope.apiVersion", "v1")

	// Add results
	resultsSlice := attrs.PutEmptySlice("results")
	resultVal := resultsSlice.AppendEmpty()
	resultVal.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "test-policy",
		"result": "pass",
		"rule": "test-rule",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should create one security event")

	// Verify the security event fields
	eventAttrs := records[0].Attributes()
	assert.Equal(t, "COMPLIANCE_FINDING", eventAttrs.AsRaw()["event.type"])
	assert.Equal(t, "COMPLIANCE", eventAttrs.AsRaw()["event.category"])
	assert.Equal(t, "COMPLIANT", eventAttrs.AsRaw()["compliance.status"])
	assert.Equal(t, "test-policy", eventAttrs.AsRaw()["compliance.requirements"])
	assert.Equal(t, "test-rule", eventAttrs.AsRaw()["compliance.control"])
}

func TestProcessLogRecord_OpenReportsLog_MultipleResults(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	// Add multiple results
	resultsSlice := attrs.PutEmptySlice("results")

	// Result 1: pass
	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "policy1",
		"result": "pass",
		"rule": "rule1",
		"scored": true
	}`)

	// Result 2: fail
	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264663, "nanos": 0},
		"message": "Policy violation",
		"policy": "policy2",
		"result": "fail",
		"rule": "rule2",
		"scored": true,
		"severity": "medium"
	}`)

	// Result 3: error
	result3 := resultsSlice.AppendEmpty()
	result3.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264664, "nanos": 0},
		"message": "Policy check error",
		"policy": "policy3",
		"result": "error",
		"rule": "rule3",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 3, "Should create three security events")

	// Verify different compliance statuses
	event1Attrs := records[0].Attributes()
	event2Attrs := records[1].Attributes()
	event3Attrs := records[2].Attributes()

	assert.Equal(t, "COMPLIANT", event1Attrs.AsRaw()["compliance.status"])
	assert.Equal(t, "NON_COMPLIANT", event2Attrs.AsRaw()["compliance.status"])
	assert.Equal(t, "NON_COMPLIANT", event3Attrs.AsRaw()["compliance.status"])
}

func TestProcessLogRecord_StatusFilter_OnlyFailures(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{
		Enabled:      true,
		StatusFilter: []string{"fail"},
	})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")

	// Add pass result
	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "policy1",
		"result": "pass",
		"rule": "rule1",
		"scored": true
	}`)

	// Add fail result
	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264663, "nanos": 0},
		"message": "Policy violation",
		"policy": "policy2",
		"result": "fail",
		"rule": "rule2",
		"scored": true
	}`)

	// Add skip result
	result3 := resultsSlice.AppendEmpty()
	result3.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264664, "nanos": 0},
		"message": "Policy check skipped",
		"policy": "policy3",
		"result": "skip",
		"rule": "rule3",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should only create security event for fail status")

	eventAttrs := records[0].Attributes()
	assert.Equal(t, "NON_COMPLIANT", eventAttrs.AsRaw()["compliance.status"])
	assert.Equal(t, "policy2", eventAttrs.AsRaw()["compliance.requirements"])
}

func TestProcessLogRecord_StatusFilter_MultipleStatuses(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{
		Enabled:      true,
		StatusFilter: []string{"fail", "error"},
	})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")

	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check passed", "policy": "policy1", "result": "pass", "rule": "rule1", "scored": true}`)

	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264663, "nanos": 0}, "message": "Policy violation", "policy": "policy2", "result": "fail", "rule": "rule2", "scored": true}`)

	result3 := resultsSlice.AppendEmpty()
	result3.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264664, "nanos": 0}, "message": "Policy check error", "policy": "policy3", "result": "error", "rule": "rule3", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 2, "Should create security events for fail and error only")
}

func TestProcessLogRecord_StatusFilter_Empty(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{
		Enabled:      true,
		StatusFilter: []string{}, // Empty filter = process all
	})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")

	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check passed", "policy": "policy1", "result": "pass", "rule": "rule1", "scored": true}`)

	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264663, "nanos": 0}, "message": "Policy violation", "policy": "policy2", "result": "fail", "rule": "rule2", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 2, "Empty filter should process all statuses")
}

func TestTransformToSecurityEvent_FieldMapping(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	result := Result{
		Source:    "kyverno",
		Timestamp: Timestamp{Seconds: 1758264662, Nanos: 0},
		Message:   "All containers must have CPU and memory resource requests and limits defined",
		Policy:    "all-containers-need-requests-and-limits",
		Result:    "fail",
		Rule:      "check-container-resources",
		Scored:    true,
		Severity:  "medium",
		Category:  "Pod Security Standards (Baseline)",
	}

	logRecord := plog.NewLogRecord()
	originalAttrs := pcommon.NewMap()
	originalAttrs.PutStr("k8s.cluster.name", "test-cluster")
	originalAttrs.PutStr("k8s.namespace.name", "test-namespace")

	metadata := map[string]interface{}{
		"scope.name":      "test-pod-123",
		"scope.namespace": "test-namespace",
		"scope.kind":      "Pod",
		"scope.uid":       "pod-uid-123",
	}

	processor.transformToSecurityEvent(&logRecord, result, metadata, originalAttrs)

	attrs := logRecord.Attributes()

	// Verify event fields
	assert.NotEmpty(t, attrs.AsRaw()["event.id"])
	assert.Equal(t, "1.309", attrs.AsRaw()["event.version"])
	assert.Equal(t, "COMPLIANCE", attrs.AsRaw()["event.category"])
	assert.Equal(t, "NON_COMPLIANT", attrs.AsRaw()["compliance.status"]) // fail -> NON_COMPLIANT
	assert.Contains(t, attrs.AsRaw()["event.description"], "Policy violation")

	// Verify finding fields
	assert.Equal(t, result.Message, attrs.AsRaw()["finding.description"])
	assert.NotEmpty(t, attrs.AsRaw()["finding.id"])
	assert.Equal(t, "MEDIUM", attrs.AsRaw()["finding.severity"])
	assert.Equal(t, "all-containers-need-requests-and-limits - check-container-resources", attrs.AsRaw()["finding.title"])

	// Verify compliance fields
	assert.Equal(t, "check-container-resources", attrs.AsRaw()["compliance.control"])
	assert.Equal(t, "all-containers-need-requests-and-limits", attrs.AsRaw()["compliance.requirements"])
	assert.Equal(t, "NON_COMPLIANT", attrs.AsRaw()["compliance.status"])
	assert.Equal(t, "Pod Security Standards (Baseline)", attrs.AsRaw()["compliance.standards"])

	// Verify risk fields
	assert.Equal(t, 6.9, attrs.AsRaw()["dt.security.risk.score"])

	// Verify object fields
	assert.Equal(t, "pod-uid-123", attrs.AsRaw()["object.id"])
	assert.Equal(t, "Pod", attrs.AsRaw()["object.type"])

	// Verify k8s fields
	assert.Equal(t, "test-cluster", attrs.AsRaw()["k8s.cluster.name"])
	assert.Equal(t, "test-namespace", attrs.AsRaw()["k8s.namespace.name"])
	assert.Equal(t, "test-pod-123", attrs.AsRaw()["k8s.pod.name"])
}

func TestFindingSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{"critical", "critical", "CRITICAL"},
		{"high", "high", "HIGH"},
		{"medium", "medium", "MEDIUM"},
		{"low", "low", "LOW"},
		{"empty", "", ""},
		{"unknown", "unknown", "MEDIUM"},                  // Unknown severity defaults to MEDIUM
		{"case sensitive critical", "Critical", "MEDIUM"}, // Case sensitive, so "Critical" != "critical"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, _ := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
			// Test that finding.severity is mapped to uppercase format
			result := Result{Severity: tt.severity}
			logRecord := plog.NewLogRecord()
			metadata := map[string]interface{}{"scope.name": "test"}

			processor.transformToSecurityEvent(&logRecord, result, metadata, pcommon.NewMap())
			severity := logRecord.Attributes().AsRaw()["finding.severity"]
			if tt.severity == "" {
				// If severity is empty, the field should not be set
				assert.Nil(t, severity)
			} else {
				assert.Equal(t, tt.expected, severity)
			}
		})
	}
}

func TestCalculateRiskScoreFromSeverity(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 10.0},
		{"high", 8.9},
		{"medium", 6.9},
		{"low", 3.9},
		{"unknown", 0.0},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			score := calculateRiskScoreFromSeverity(tt.severity)
			assert.Equal(t, tt.expected, score)
		})
	}
}

func TestMapResultToComplianceStatus(t *testing.T) {
	tests := []struct {
		result   string
		expected string
	}{
		{"pass", "COMPLIANT"},
		{"fail", "NON_COMPLIANT"},
		{"error", "NON_COMPLIANT"},
		{"skip", "NON_COMPLIANT"},
		{"unknown", "NON_COMPLIANT"},
		{"", "NON_COMPLIANT"},
	}

	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			status := mapResultToComplianceStatus(tt.result)
			assert.Equal(t, tt.expected, status)
		})
	}
}

func TestExtractWorkloadInfo_FromOwnerReferences(t *testing.T) {
	attrs := pcommon.NewMap()
	ownerRefsSlice := attrs.PutEmptySlice("metadata.ownerReferences")

	ownerRef := ownerRefsSlice.AppendEmpty()
	ownerRef.SetStr(`{"kind":"Pod","name":"cert-manager-cainjector-89fd4b8f9-t9xlf","uid":"109282b0-eec4-4f04-86f6-bbb0b8a6dd1e","apiVersion":"v1"}`)

	// Add Deployment owner reference
	deploymentRef := ownerRefsSlice.AppendEmpty()
	deploymentRef.SetStr(`{"kind":"Deployment","name":"cert-manager-cainjector","uid":"deployment-uid-123","apiVersion":"apps/v1"}`)

	info := extractWorkloadInfo(attrs, "cert-manager-cainjector-89fd4b8f9-t9xlf", "cert-manager")

	assert.Equal(t, "cert-manager-cainjector", info.name)
	assert.Equal(t, "Deployment", info.kind)
	assert.Equal(t, "deployment-uid-123", info.uid)
	assert.Equal(t, "cert-manager", info.namespace)
}

func TestExtractWorkloadInfo_FromPodName(t *testing.T) {
	attrs := pcommon.NewMap()
	// No owner references

	info := extractWorkloadInfo(attrs, "cert-manager-cainjector-89fd4b8f9-t9xlf", "cert-manager")

	assert.Equal(t, "cert-manager-cainjector", info.name)
	assert.Equal(t, "Deployment", info.kind) // Defaults to Deployment
	assert.Equal(t, "cert-manager", info.namespace)
}

func TestExtractWorkloadInfo_StatefulSet(t *testing.T) {
	attrs := pcommon.NewMap()
	ownerRefsSlice := attrs.PutEmptySlice("metadata.ownerReferences")

	statefulSetRef := ownerRefsSlice.AppendEmpty()
	statefulSetRef.SetStr(`{"kind":"StatefulSet","name":"my-statefulset","uid":"ss-uid-123","apiVersion":"apps/v1"}`)

	info := extractWorkloadInfo(attrs, "my-statefulset-0", "default")

	assert.Equal(t, "my-statefulset", info.name)
	assert.Equal(t, "StatefulSet", info.kind)
	assert.Equal(t, "ss-uid-123", info.uid)
}

func TestIsWorkloadKind(t *testing.T) {
	tests := []struct {
		kind     string
		expected bool
	}{
		{"Deployment", true},
		{"StatefulSet", true},
		{"DaemonSet", true},
		{"Job", true},
		{"CronJob", true},
		{"ReplicaSet", true},
		{"Pod", false},
		{"Service", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			result := isWorkloadKind(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitPodName(t *testing.T) {
	tests := []struct {
		podName  string
		expected []string
	}{
		{"cert-manager-cainjector-89fd4b8f9-t9xlf", []string{"cert", "manager", "cainjector", "89fd4b8f9", "t9xlf"}},
		{"simple-pod", []string{"simple", "pod"}},
		{"pod", []string{"pod"}},
		{"a-b-c-d-e", []string{"a", "b", "c", "d", "e"}},
	}

	for _, tt := range tests {
		t.Run(tt.podName, func(t *testing.T) {
			result := splitPodName(tt.podName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessLogRecord_InvalidJSON(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")

	// Invalid JSON
	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{invalid json}`)

	// Valid JSON
	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check passed", "policy": "policy1", "result": "pass", "rule": "rule1", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should only process valid JSON results")
}

func TestProcessLogRecord_WithSeverityAndCategory(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")
	result := resultsSlice.AppendEmpty()
	result.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy violation",
		"policy": "test-policy",
		"result": "fail",
		"rule": "test-rule",
		"scored": true,
		"severity": "high",
		"category": "Pod Security Standards (Baseline)"
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1)

	eventAttrs := records[0].Attributes()
	assert.Equal(t, 8.9, eventAttrs.AsRaw()["dt.security.risk.score"])
	assert.Equal(t, "HIGH", eventAttrs.AsRaw()["finding.severity"])
	assert.Equal(t, "Pod Security Standards (Baseline)", eventAttrs.AsRaw()["compliance.standards"])
}

func TestProcessLogRecord_TimestampMapping(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(1758264665, 0)))

	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	resultsSlice := attrs.PutEmptySlice("results")
	result := resultsSlice.AppendEmpty()
	result.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 500000000},
		"message": "Policy violation",
		"policy": "test-policy",
		"result": "fail",
		"rule": "test-rule",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1)

	// Verify timestamp was set from result
	expectedTime := time.Unix(1758264662, 500000000)
	assert.Equal(t, pcommon.NewTimestampFromTime(expectedTime), records[0].Timestamp())

	// Verify finding.time.created field
	eventAttrs := records[0].Attributes()
	createdTime := eventAttrs.AsRaw()["finding.time.created"]
	assert.NotEmpty(t, createdTime)
	assert.Contains(t, createdTime.(string), "2025-09-19") // Approximate date check
}

func TestProcessLogRecord_Deduplication_FirstTimeAllResults(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "test-pod")
	attrs.PutStr("scope.namespace", "test-namespace")
	attrs.PutStr("scope.kind", "Pod")
	attrs.PutStr("scope.uid", "test-uid-123")

	// Add 3 results
	resultsSlice := attrs.PutEmptySlice("results")
	result1 := resultsSlice.AppendEmpty()
	result1.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check 1", "policy": "policy1", "result": "fail", "rule": "rule1", "scored": true}`)

	result2 := resultsSlice.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264663, "nanos": 0}, "message": "Policy check 2", "policy": "policy2", "result": "fail", "rule": "rule2", "scored": true}`)

	result3 := resultsSlice.AppendEmpty()
	result3.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264664, "nanos": 0}, "message": "Policy check 3", "policy": "policy3", "result": "fail", "rule": "rule3", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	// First call - should process all 3 results
	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 3, "First time should process all results")
}

func TestProcessLogRecord_Deduplication_SubsequentTimeOnlyLatest(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	// First call with 2 results
	logRecord1 := plog.NewLogRecord()
	attrs1 := logRecord1.Attributes()
	attrs1.PutStr("kind", "Report")
	attrs1.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs1.PutStr("scope.name", "test-pod")
	attrs1.PutStr("scope.namespace", "test-namespace")
	attrs1.PutStr("scope.kind", "Pod")
	attrs1.PutStr("scope.uid", "test-uid-123")

	resultsSlice1 := attrs1.PutEmptySlice("results")
	result1 := resultsSlice1.AppendEmpty()
	result1.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check 1", "policy": "policy1", "result": "fail", "rule": "rule1", "scored": true}`)

	result2 := resultsSlice1.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264663, "nanos": 0}, "message": "Policy check 2", "policy": "policy2", "result": "fail", "rule": "rule2", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	// First call - should process all 2 results
	records1, err := processor.ProcessLogRecord(context.Background(), &logRecord1, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records1)
	assert.Len(t, records1, 2, "First time should process all results")

	// Second call with same 2 results + 1 new result (total 3)
	logRecord2 := plog.NewLogRecord()
	attrs2 := logRecord2.Attributes()
	attrs2.PutStr("kind", "Report")
	attrs2.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs2.PutStr("scope.name", "test-pod")
	attrs2.PutStr("scope.namespace", "test-namespace")
	attrs2.PutStr("scope.kind", "Pod")
	attrs2.PutStr("scope.uid", "test-uid-123")

	resultsSlice2 := attrs2.PutEmptySlice("results")
	// Same first result
	result1Again := resultsSlice2.AppendEmpty()
	result1Again.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check 1", "policy": "policy1", "result": "fail", "rule": "rule1", "scored": true}`)

	// Same second result
	result2Again := resultsSlice2.AppendEmpty()
	result2Again.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264663, "nanos": 0}, "message": "Policy check 2", "policy": "policy2", "result": "fail", "rule": "rule2", "scored": true}`)

	// New third result (latest)
	result3New := resultsSlice2.AppendEmpty()
	result3New.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264664, "nanos": 0}, "message": "Policy check 3", "policy": "policy3", "result": "fail", "rule": "rule3", "scored": true}`)

	// Second call - should only process the latest (3rd) result
	records2, err := processor.ProcessLogRecord(context.Background(), &logRecord2, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records2)
	assert.Len(t, records2, 1, "Subsequent time should only process latest result")

	// Verify it's the new result
	eventAttrs := records2[0].Attributes()
	assert.Equal(t, "policy3", eventAttrs.AsRaw()["compliance.requirements"])
	assert.Equal(t, "rule3", eventAttrs.AsRaw()["compliance.control"])
}

func TestProcessLogRecord_Deduplication_DifferentPods(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	// Process results for pod 1
	logRecord1 := plog.NewLogRecord()
	attrs1 := logRecord1.Attributes()
	attrs1.PutStr("kind", "Report")
	attrs1.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs1.PutStr("scope.name", "pod-1")
	attrs1.PutStr("scope.namespace", "test-namespace")
	attrs1.PutStr("scope.kind", "Pod")
	attrs1.PutStr("scope.uid", "pod-1-uid")

	resultsSlice1 := attrs1.PutEmptySlice("results")
	result1 := resultsSlice1.AppendEmpty()
	result1.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check", "policy": "policy1", "result": "fail", "rule": "rule1", "scored": true}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records1, err := processor.ProcessLogRecord(context.Background(), &logRecord1, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records1)
	assert.Len(t, records1, 1, "Should process result for pod 1")

	// Process results for pod 2 (different pod)
	logRecord2 := plog.NewLogRecord()
	attrs2 := logRecord2.Attributes()
	attrs2.PutStr("kind", "Report")
	attrs2.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs2.PutStr("scope.name", "pod-2")
	attrs2.PutStr("scope.namespace", "test-namespace")
	attrs2.PutStr("scope.kind", "Pod")
	attrs2.PutStr("scope.uid", "pod-2-uid")

	resultsSlice2 := attrs2.PutEmptySlice("results")
	result2 := resultsSlice2.AppendEmpty()
	result2.SetStr(`{"source": "kyverno", "timestamp": {"seconds": 1758264662, "nanos": 0}, "message": "Policy check", "policy": "policy1", "result": "fail", "rule": "rule1", "scored": true}`)

	// Should process all results for pod 2 (first time for this pod)
	records2, err := processor.ProcessLogRecord(context.Background(), &logRecord2, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records2)
	assert.Len(t, records2, 1, "Should process result for pod 2 (first time for this pod)")
}

func TestProcessLogRecord_StatefulSet_ExtractsK8sStatefulSetName(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "otel-collector")
	attrs.PutStr("scope.namespace", "default")
	attrs.PutStr("scope.kind", "StatefulSet")
	attrs.PutStr("scope.uid", "f7cffc67-15a8-4862-9b01-a020abed643e")

	// Add results
	resultsSlice := attrs.PutEmptySlice("results")
	resultVal := resultsSlice.AppendEmpty()
	resultVal.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "restrict-sysctls",
		"result": "pass",
		"rule": "autogen-check-sysctls",
		"scored": true,
		"severity": "medium"
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should create one security event")

	// Verify the security event has k8s.statefulset.name set
	eventAttrs := records[0].Attributes()
	assert.Equal(t, "StatefulSet", eventAttrs.AsRaw()["object.type"])
	assert.Equal(t, "otel-collector", eventAttrs.AsRaw()["object.name"])
	assert.Equal(t, "otel-collector", eventAttrs.AsRaw()["k8s.statefulset.name"], "k8s.statefulset.name should be set from scope.name when scope.kind is StatefulSet")
	assert.Equal(t, "f7cffc67-15a8-4862-9b01-a020abed643e", eventAttrs.AsRaw()["k8s.workload.uid"])
}

func TestProcessLogRecord_Deployment_ExtractsK8sDeploymentName(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "my-deployment")
	attrs.PutStr("scope.namespace", "default")
	attrs.PutStr("scope.kind", "Deployment")
	attrs.PutStr("scope.uid", "deployment-uid-123")

	// Add results
	resultsSlice := attrs.PutEmptySlice("results")
	resultVal := resultsSlice.AppendEmpty()
	resultVal.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "test-policy",
		"result": "pass",
		"rule": "test-rule",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should create one security event")

	// Verify the security event has k8s.deployment.name set
	eventAttrs := records[0].Attributes()
	assert.Equal(t, "Deployment", eventAttrs.AsRaw()["object.type"])
	assert.Equal(t, "my-deployment", eventAttrs.AsRaw()["object.name"])
	assert.Equal(t, "my-deployment", eventAttrs.AsRaw()["k8s.deployment.name"], "k8s.deployment.name should be set from scope.name when scope.kind is Deployment")
}

func TestProcessLogRecord_DaemonSet_ExtractsK8sDaemonSetName(t *testing.T) {
	processor, err := NewProcessor(zaptest.NewLogger(t), &Config{Enabled: true})
	require.NoError(t, err)

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()
	attrs.PutStr("kind", "Report")
	attrs.PutStr("apiVersion", "openreports.io/v1alpha1")
	attrs.PutStr("scope.name", "my-daemonset")
	attrs.PutStr("scope.namespace", "kube-system")
	attrs.PutStr("scope.kind", "DaemonSet")
	attrs.PutStr("scope.uid", "daemonset-uid-123")

	// Add results
	resultsSlice := attrs.PutEmptySlice("results")
	resultVal := resultsSlice.AppendEmpty()
	resultVal.SetStr(`{
		"source": "kyverno",
		"timestamp": {"seconds": 1758264662, "nanos": 0},
		"message": "Policy check passed",
		"policy": "test-policy",
		"result": "pass",
		"rule": "test-rule",
		"scored": true
	}`)

	resource := pcommon.NewResource()
	scopeLogs := plog.NewScopeLogs()

	records, err := processor.ProcessLogRecord(context.Background(), &logRecord, resource, scopeLogs)
	assert.NoError(t, err)
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should create one security event")

	// Verify the security event has k8s.daemonset.name set
	eventAttrs := records[0].Attributes()
	assert.Equal(t, "DaemonSet", eventAttrs.AsRaw()["object.type"])
	assert.Equal(t, "my-daemonset", eventAttrs.AsRaw()["object.name"])
	assert.Equal(t, "my-daemonset", eventAttrs.AsRaw()["k8s.daemonset.name"], "k8s.daemonset.name should be set from scope.name when scope.kind is DaemonSet")
}
