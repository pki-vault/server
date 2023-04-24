package db

import (
	"errors"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"strings"
)

type MigrationDriver interface {
	MigrationDriver() (database.Driver, error)
}

func RunMigrations(backend SqlBackend, migrationsBasePath string) error {
	var driver database.Driver
	var err error
	var sourceURL string

	driver, err = backend.MigrationDriver()
	if err != nil {
		return err
	}

	switch backend.DatabaseType() {
	case PostgresqlDatabaseType:
		sourceURL = fmt.Sprintf("file://%s/postgresql", strings.TrimPrefix(migrationsBasePath, "/"))
	default:
		return errors.New(fmt.Sprintf("Unsupported database driver '%s'", backend.DatabaseType()))
	}

	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		return err
	}
	return m.Up()
}
