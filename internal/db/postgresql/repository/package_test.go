package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/pki-vault/server/internal/db"
	"github.com/pki-vault/server/internal/db/postgresql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"testing"
	"time"
)

var (
	testPostgresqlImage     = "postgres:14"
	testPostgresqlUser      = "test"
	testPostgresqlPassword  = "test"
	testPostgresqlDB        = "test"
	postgresqlTestContainer testcontainers.Container
	postgresqlTestBackend   *postgresql.Backend
)

func setupPostgresqlTestBackend() {
	natPort, err := nat.NewPort("tcp", "5432")
	if err != nil {
		panic(err)
	}
	port, err := postgresqlTestContainer.MappedPort(context.Background(), natPort)
	if err != nil {
		panic(err)
	}
	dbPool, err := sql.Open("postgres",
		fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s?sslmode=disable",
			testPostgresqlUser, testPostgresqlPassword, port.Int(), testPostgresqlDB))
	if err != nil {
		panic(err)
	}

	postgresqlTestBackend = postgresql.NewBackend(dbPool)

	err = db.RunMigrations(postgresqlTestBackend, "./../../migrations")
	if err != nil {
		panic(err)
	}
}

func testContainer(ctx context.Context) (testcontainers.Container, error) {
	// Define a PostgreSQL container with the desired configuration
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        testPostgresqlImage,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     testPostgresqlUser,
				"POSTGRES_PASSWORD": testPostgresqlPassword,
				"POSTGRES_DB":       testPostgresqlDB,
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections"),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}

	// Wait for 1 more second before connecting to the PostgreSQL database
	time.Sleep(1 * time.Second)

	return container, nil
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	postgresqlTestContainer, err = testContainer(ctx)
	if err != nil {
		panic(err)
	}

	defer func(container testcontainers.Container, ctx context.Context) {
		err := container.Terminate(ctx)
		if err != nil {
			panic(err)
		}
	}(postgresqlTestContainer, ctx)

	setupPostgresqlTestBackend()

	// Run the tests
	code := m.Run()

	os.Exit(code)
}
