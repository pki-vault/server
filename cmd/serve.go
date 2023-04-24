package cmd

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/pki-vault/server/internal/validation"
	"github.com/pki-vault/server/internal/wire"
	"github.com/spf13/cobra"
)

var (
	serveConfigFile string
	serveConfigType string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the app serve its http API",
	Long:  `Runs and exposes the http API via the addresses configured in the config file.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := loadConfig(serveConfigFile, serveConfigType)
		if err != nil {
			panic(err)
		}
		gin.SetMode(config.Mode)

		if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
			if err := validation.RegisterCustomValidators(v); err != nil {
				panic("Failed to register custom validators")
			}
		} else {
			panic("Expected a validator")
		}

		repositoryBundle, closeDbFunc, err := wire.InitializePostgresqlRepositoryBundle(wire.DataSourceName(config.DSN))
		engine, err := wire.ProvideGinEngine(repositoryBundle)

		err = engine.Run(config.ListenAddresses...)
		if err != nil {
			panic(err)
		}
		closeDbFunc()
	},
}

func init() {
	initConfig(serveCmd, &serveConfigFile, &serveConfigType)
	RootCmd.AddCommand(serveCmd)
}
