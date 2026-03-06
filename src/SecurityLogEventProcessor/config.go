package securityevent

import (
	"github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor/internal/openreports"
)

// Config defines the configuration for the security event processor
type Config struct {
	// Processors defines the list of enabled processors
	Processors ProcessorConfig `mapstructure:"processors"`
}

// ProcessorConfig contains configuration for individual processor types
type ProcessorConfig struct {
	// OpenReports configuration
	OpenReports openreports.Config `mapstructure:"openreports"`
}

// Validate checks if the configuration is valid
func (cfg *Config) Validate() error {
	if err := cfg.Processors.OpenReports.Validate(); err != nil {
		return err
	}
	return nil
}
