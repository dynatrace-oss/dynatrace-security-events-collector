package securityevent

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

var (
	typeStr   = component.MustNewType("securityevent")
	stability = component.StabilityLevelDevelopment
)

// NewFactory creates a new processor factory
func NewFactory() processor.Factory {
	return processor.NewFactory(
		typeStr,
		createDefaultConfig,
		processor.WithLogs(createLogsProcessor, stability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Processors: ProcessorConfig{},
	}
}

func createLogsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (processor.Logs, error) {
	oCfg := cfg.(*Config)

	processorInstance, err := newSecurityEventProcessor(set.Logger, oCfg, set.TelemetrySettings)
	if err != nil {
		return nil, err
	}

	return processorhelper.NewLogs(
		ctx,
		set,
		cfg,
		nextConsumer,
		processorInstance.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
	)
}
