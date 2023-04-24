package db

import (
	"database/sql"
)

type SQLDatabaseType = string

var (
	PostgresqlDatabaseType = "postgresql"
)

type SqlBackend interface {
	MigrationDriver
	Db() *sql.DB
	DatabaseType() SQLDatabaseType
}
