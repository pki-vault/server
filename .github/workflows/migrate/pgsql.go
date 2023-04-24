package main

import (
	"database/sql"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"os"
)

func main() {
	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		"postgres", os.Getenv("PSQL_PASS"), os.Getenv("PSQL_PORT"), "postgres"))
	if err != nil {
		panic(err)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://internal/db/migrations/postgresql", "postgres", driver)
	if err != nil {
		panic(err)
	}
	m.Up()
}
