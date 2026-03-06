package exporter

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/config/configopaque"
)

// Config defines the configuration for the security event exporter
type Config struct {
	// Endpoint is the HTTP endpoint where security events will be sent
	Endpoint string `mapstructure:"endpoint"`

	// Timeout is the HTTP request timeout
	Timeout time.Duration `mapstructure:"timeout"`

	// Headers are additional HTTP headers to include in requests
	Headers map[string]configopaque.String `mapstructure:"headers"`

	// DefaultAttributes are attributes that will be added to all security events
	DefaultAttributes map[string]interface{} `mapstructure:"default_attributes"`

	// RetrySettings configures retry behavior (simplified for now)
	RetrySettings map[string]interface{} `mapstructure:"retry_on_failure"`

	// QueueSettings configures queue behavior (simplified for now)
	QueueSettings map[string]interface{} `mapstructure:"sending_queue"`
}

// Validate validates the configuration
func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("endpoint is required")
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	return nil
}

// createDefaultRetrySettings creates default retry settings
func createDefaultRetrySettings() map[string]interface{} {
	return map[string]interface{}{
		"enabled":              true,
		"initial_interval":     "5s",
		"randomization_factor": 0.5,
		"multiplier":           1.5,
		"max_interval":         "30s",
		"max_elapsed_time":     "5m",
	}
}

// createDefaultQueueSettings creates default queue settings
func createDefaultQueueSettings() map[string]interface{} {
	return map[string]interface{}{
		"enabled":       true,
		"num_consumers": 10,
		"queue_size":    1000,
	}
}
