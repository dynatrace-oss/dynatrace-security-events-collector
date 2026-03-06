package exporter

import (
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Endpoint: "https://example.com/events",
				Timeout:  30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "missing endpoint",
			config: Config{
				Endpoint: "",
				Timeout:  30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			config: Config{
				Endpoint: "https://example.com/events",
				Timeout:  0,
			},
			wantErr: false, // Should set default timeout
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateDefaultRetrySettings(t *testing.T) {
	settings := createDefaultRetrySettings()

	if settings == nil {
		t.Error("createDefaultRetrySettings() returned nil")
	}

	if settings["enabled"] != true {
		t.Error("Default retry settings should have enabled = true")
	}
}

func TestCreateDefaultQueueSettings(t *testing.T) {
	settings := createDefaultQueueSettings()

	if settings == nil {
		t.Error("createDefaultQueueSettings() returned nil")
	}

	if settings["enabled"] != true {
		t.Error("Default queue settings should have enabled = true")
	}
}
