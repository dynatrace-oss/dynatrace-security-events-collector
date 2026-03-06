package securityevent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)

	assert.Equal(t, component.MustNewType("securityevent"), factory.Type())
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	config := factory.CreateDefaultConfig()

	require.NotNil(t, config)

	cfg, ok := config.(*Config)
	require.True(t, ok, "Config should be of type *Config")

	// Validate default config
	err := cfg.Validate()
	require.NoError(t, err)

	// OpenReports should default to disabled
	assert.False(t, cfg.Processors.OpenReports.Enabled)
}

// Note: Factory tests for CreateLogsProcessor would require integration with processorhelper
// which is tested through the processor itself. These basic factory tests verify the factory
// can be created and default config is valid.
