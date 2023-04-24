package postgresql

import (
	"database/sql"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/pki-vault/server/internal/db"
)

type Backend struct {
	db *sql.DB
}

func NewBackend(db *sql.DB) *Backend {
	return &Backend{db: db}
}

func (p *Backend) DatabaseType() db.SQLDatabaseType {
	return db.PostgresqlDatabaseType
}

func (p *Backend) Db() *sql.DB {
	return p.db
}

func (p *Backend) MigrationDriver() (database.Driver, error) {
	return postgres.WithInstance(p.db, &postgres.Config{})
}
