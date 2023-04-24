package cmd

import (
	"errors"
	"github.com/golang-migrate/migrate/v4"
	"github.com/pki-vault/server/internal/db"
	"github.com/pki-vault/server/internal/wire"
	"github.com/spf13/cobra"
)

var (
	migrateConfigFile string
	migrateConfigType string
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long: `Runs database migrations for the application. It uses the configured database backend to apply 
			any pending database migrations found in the specified migrations directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := loadConfig(migrateConfigFile, migrateConfigType)
		if err != nil {
			panic(err)
		}
		dbBackend, closeDbFunc, err := wire.InitializePostgresqlBackend(wire.DataSourceName(config.DSN))
		if err != nil {
			panic(err)
		}

		err = db.RunMigrations(dbBackend, config.Migration.BasePath)
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			panic(err)
		}
		closeDbFunc()
	},
}

func init() {
	initConfig(migrateCmd, &migrateConfigFile, &migrateConfigType)
	RootCmd.AddCommand(migrateCmd)
}
