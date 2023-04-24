//go:build wireinject
// +build wireinject

package wire

import (
	"database/sql"
	"github.com/google/wire"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/postgresql"
	postgresqlrepository "github.com/pki-vault/server/internal/db/postgresql/repository"
)

type DataSourceName string

func InitializePostgresqlDb(dataSourceName DataSourceName) (*sql.DB, func(), error) {
	sqlDb, err := sql.Open("postgres", string(dataSourceName))
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		if err := sqlDb.Close(); err != nil {
			panic(err)
		}
	}
	return sqlDb, cleanup, err
}

func InitializePostgresqlBackend(dataSourceName DataSourceName) (*postgresql.Backend, func(), error) {
	wire.Build(
		postgresql.NewBackend,
		InitializePostgresqlDb,
	)
	return &postgresql.Backend{}, nil, nil
}

func InitializePostgresqlRepositoryBundle(dataSourceName DataSourceName) (*postgresqlrepository.Bundle, func(), error) {
	wire.Build(
		postgresqlrepository.NewRepositoryBundle,
		InitializePostgresqlDb,
		postgresqlrepository.NewX509CertificateRepository,
		postgresqlrepository.NewX509CertificateSubscriptionRepository,
		postgresqlrepository.NewX509PrivateKeyRepository,
		postgresqlrepository.NewTransactionManager,
		clockwork.NewRealClock,
	)
	return new(postgresqlrepository.Bundle), nil, nil
}
