package openreports

import "fmt"

// Config defines the configuration for the OpenReports processor
type Config struct {
	// Enabled indicates whether the OpenReports processor is enabled
	Enabled bool `mapstructure:"enabled"`

	// StatusFilter is an array of result statuses to process
	// Only results with statuses in this list will be transformed into security events
	// Valid values: "pass", "fail", "error", "skip"
	// If empty or not specified, all statuses will be processed
	StatusFilter []string `mapstructure:"status_filter"`
}

// Validate checks if the configuration is valid
func (cfg *Config) Validate() error {
	// Validate status filter values
	validStatuses := map[string]bool{
		"pass":  true,
		"fail":  true,
		"error": true,
		"skip":  true,
	}

	for _, status := range cfg.StatusFilter {
		if !validStatuses[status] {
			return fmt.Errorf("invalid status in status_filter: %s. Valid values are: pass, fail, error, skip", status)
		}
	}

	return nil
}
