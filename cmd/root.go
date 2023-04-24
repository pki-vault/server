package cmd

import (
	"errors"
	"fmt"
	"github.com/pki-vault/server/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var RootCmd = &cobra.Command{}

func initConfig(cmd *cobra.Command, configFile *string, configType *string) {
	cmd.PersistentFlags().StringVarP(configFile, "config", "c", "", "Path to the config file")
	err := cmd.MarkPersistentFlagRequired("config")
	if err != nil {
		panic(err)
	}

	cmd.PersistentFlags().StringVarP(configType, "config-type", "", "yaml", "DatabaseType of the config")
}

func loadConfig(configFile string, configType string) (*config.Config, error) {
	if configFile == "" {
		return nil, errors.New("config file (--config) is required")
	}

	viper.SetConfigFile(configFile)
	viper.SetConfigType(configType)
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
