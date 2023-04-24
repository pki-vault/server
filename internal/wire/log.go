package wire

import "go.uber.org/zap"

func InitializeZapLogger() (*zap.Logger, error) {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	return config.Build()
}
