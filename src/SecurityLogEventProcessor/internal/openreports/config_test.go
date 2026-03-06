package openreports

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_ValidStatuses(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "empty filter",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{},
			},
			wantErr: false,
		},
		{
			name: "single valid status",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"fail"},
			},
			wantErr: false,
		},
		{
			name: "multiple valid statuses",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"pass", "fail", "error", "skip"},
			},
			wantErr: false,
		},
		{
			name: "pass and fail",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"pass", "fail"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_InvalidStatuses(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid status",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"invalid"},
			},
			wantErr: true,
			errMsg:  "invalid status in status_filter: invalid",
		},
		{
			name: "mixed valid and invalid",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"pass", "invalid", "fail"},
			},
			wantErr: true,
			errMsg:  "invalid status in status_filter: invalid",
		},
		{
			name: "empty string",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{""},
			},
			wantErr: true,
		},
		{
			name: "case sensitive - uppercase",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"FAIL"},
			},
			wantErr: true,
		},
		{
			name: "case sensitive - mixed case",
			config: Config{
				Enabled:      true,
				StatusFilter: []string{"Pass"},
			},
			wantErr: true,
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
