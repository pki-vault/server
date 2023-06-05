SHELL=/bin/bash -o pipefail

export PATH := $(PATH):$(shell go env GOPATH)/bin

TOOLS = \
    "github.com/volatiletech/sqlboiler/v4@latest" \
    "github.com/volatiletech/sqlboiler/v4/drivers/sqlboiler-psql@latest" \
    "github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest" \
    "github.com/google/wire/cmd/wire@latest" \
    "github.com/golang/mock/mockgen@v1.6.0" \
    "github.com/joho/godotenv/cmd/godotenv@latest"

.make/install-tools: go.mod go.sum
	@for tool in $(TOOLS); do \
		echo "Installing $$tool..."; \
		go install $$tool; \
	done
	touch $@

.PHONY: migrate-postgresql
migrate-postgresql: .make/install-tools
	godotenv go run .github/workflows/migrate/pgsql.go

.PHONY: generate-all
generate-all: generate-sqlboiler generate-openapi-boilerplate generate-go generate-test-certificates

.PHONY: generate-go
generate-go: .make/install-tools
	go generate ./...

.PHONY: generate-sqlboiler
generate-sqlboiler: .make/install-tools
	godotenv sqlboiler psql -c sqlboiler.toml -o internal/db/postgresql/models -p models

.PHONY: generate-openapi-boilerplate
generate-openapi-boilerplate:
	oapi-codegen -config .openapi/oapi-codegen.cfg.yaml .openapi/openapi.yaml

.PHONY: generate-test-certificates
generate-test-certificates:
	bash testdata/certificates/generate.sh

.PHONY: go-test
go-test: .make/install-tools
	godotenv go test -v ./...