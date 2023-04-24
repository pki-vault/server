package config

import "github.com/spf13/viper"

type Mode string

var (
	ModeRelease Mode = "release"
	ModeDebug   Mode = "debug"
)

type Config struct {
	Mode            string    `mapstructure:"mode"`
	DSN             string    `mapstructure:"dsn"`
	Migration       Migration `mapstructure:"migration"`
	ListenAddresses []string  `mapstructure:"listen_addresses"`
}

type Migration struct {
	BasePath string `mapstructure:"basePath"`
}

func (c *Config) GetModeOrDefault(defaultMode Mode) Mode {
	configMode := Mode(c.Mode)
	switch configMode {
	case ModeRelease, ModeDebug:
		return configMode
	default:
		return defaultMode
	}
}

func init() {
	viper.SetDefault("migration.basePath", "internal/db/migrations")
}
