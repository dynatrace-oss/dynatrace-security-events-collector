package securityevent

import (
	"testing"

	"github.com/dynatrace-oss/dynatrace-security-events-collector/src/SecurityLogEventProcessor/internal/openreports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_ValidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "empty config",
			config: Config{
				Processors: ProcessorConfig{},
			},
		},
		{
			name: "openreports enabled with valid status filter",
			config: Config{
				Processors: ProcessorConfig{
					OpenReports: openreports.Config{
						Enabled:      true,
						StatusFilter: []string{"fail", "error"},
					},
				},
			},
		},
		{
			name: "openreports enabled with empty status filter",
			config: Config{
				Processors: ProcessorConfig{
					OpenReports: openreports.Config{
						Enabled:      true,
						StatusFilter: []string{},
					},
				},
			},
		},
		{
			name: "openreports disabled",
			config: Config{
				Processors: ProcessorConfig{
					OpenReports: openreports.Config{
						Enabled: false,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.NoError(t, err)
		})
	}
}

func TestConfig_Validate_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid status filter",
			config: Config{
				Processors: ProcessorConfig{
					OpenReports: openreports.Config{
						Enabled:      true,
						StatusFilter: []string{"invalid"},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid status in status_filter: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestProcessorConfig_Empty(t *testing.T) {
	config := ProcessorConfig{}

	// Should be valid
	err := config.OpenReports.Validate()
	require.NoError(t, err)

	// Should default to disabled
	assert.False(t, config.OpenReports.Enabled)
}
