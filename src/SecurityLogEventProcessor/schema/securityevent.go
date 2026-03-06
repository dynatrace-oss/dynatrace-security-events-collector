// Package schema defines the security event schema used for transforming
// various log formats (e.g., OpenReports) into standardized security events.
package schema

// SecurityEvent represents a standardized security event log entry
// This schema will be populated based on the examples provided
type SecurityEvent struct {
	// EventType indicates the type of security event
	EventType string `json:"event_type"`

	// Timestamp when the event occurred
	Timestamp string `json:"timestamp"`

	// Source of the event
	Source Source `json:"source"`

	// Target of the event
	Target Target `json:"target"`

	// Action performed
	Action Action `json:"action"`

	// Result of the action
	Result Result `json:"result"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Source represents the source of the security event
type Source struct {
	// User who initiated the event
	User string `json:"user,omitempty"`

	// IP address of the source
	IPAddress string `json:"ip_address,omitempty"`

	// Application/service name
	Application string `json:"application,omitempty"`

	// Additional source fields
	Additional map[string]interface{} `json:"additional,omitempty"`
}

// Target represents the target of the security event
type Target struct {
	// Resource being accessed
	Resource string `json:"resource,omitempty"`

	// Resource type
	ResourceType string `json:"resource_type,omitempty"`

	// Additional target fields
	Additional map[string]interface{} `json:"additional,omitempty"`
}

// Action represents the action performed
type Action struct {
	// Action type (e.g., "read", "write", "delete", "execute")
	Type string `json:"type"`

	// Action description
	Description string `json:"description,omitempty"`

	// Additional action fields
	Additional map[string]interface{} `json:"additional,omitempty"`
}

// Result represents the result of the action
type Result struct {
	// Status (e.g., "success", "failure", "denied")
	Status string `json:"status"`

	// Status code if applicable
	StatusCode int `json:"status_code,omitempty"`

	// Error message if applicable
	ErrorMessage string `json:"error_message,omitempty"`

	// Additional result fields
	Additional map[string]interface{} `json:"additional,omitempty"`
}
