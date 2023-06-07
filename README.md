# PKI Vault Server

[![codecov](https://codecov.io/gh/pki-vault/server/branch/main/graph/badge.svg?token=P2G4BSOGDL)](https://codecov.io/gh/pki-vault/server)

The server component of the PKI Vault responsible for storing and managing certificates
and their keys.

:warning: **This project is still in development and not ready for production use.**

## Features

* REST API for managing certificates and keys (mostly only insertion and retrieval of the latest version of a
  certificate with certain characteristics)
* Automatic linking of certificate chains and keys no matter in which order or when they are inserted
* Certificate subscriptions: Clients can subscribe to certificates with certain characteristics and can retrieve the
  latest usable version. Available characteristics are only subject alternative names + common name for now.
* Architecture support for multiple databases (only implementation is PostgreSQL at the moment)

## Supported Databases

The following databases and versions are supported and were tested:

* **PostgreSQL** >= 14.7

It is possible that other versions will work, but there is no guarantee.

If you need support for other databases consider creating a pull request with an implementation
or [open an issue](https://github.com/pki-vault/server/issues). An example implementation can be found at
[internal/db/postgresql](internal/db/postgresql).

## Usage
Currently, there is no release available or docker image, so you have to build the binary yourself.

### Build

Before you build the binary, you have to make sure all generated code is up-to-date.
Execute the following commands to generate all code:
```sh
make generate-all
go build
```

Note: To generate all code the postgresql database must be running. See [Development Code Generation](#code-generation)
for more information.

### Config Setup

A development config file is provided at [config.dev.yml](config.dev.yml) and can be adapted to run the service.

### Generate Clients

The Http REST API of this server is generated from the spec at [.openapi/openapi.yaml](.openapi/openapi.yaml) with
strict types.

Currently, there are no pre-generated clients available for use.
It is planned to provide these, but for now you have to generate them yourself.
Code generators that can be used for this are for example
[openapi-generator.tech](https://openapi-generator.tech)
or [oapi-codegen (Golang only)](https://github.com/deepmap/oapi-codegen)

## Development

### System Requirements

* Golang >= 1.20
* [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) or equivalent tools
  like [Podman](https://podman.io/) and [Podman Compose](https://github.com/containers/podman-compose) for the dev
  containers
* `make` on Linux or an equivalent tool on other platforms

### Architecture

The server is built with a layered architecture in mind. The layers are as follows:

* **REST API**: The REST API layer is responsible for handling HTTP requests and responses. It is also responsible for
  authentication and authorization. Code resides in the [internal/restserver](internal/restserver) package.
* **Service**: The service layer is responsible for handling business logic. It is the layer that is used by the REST
  API layer. Code resides in the [internal/service](internal/service) package.
* **Repository**: The repository layer is responsible for handling database access. It is the layer that is used by the
  service layer. Code resides in the [internal/db](internal/db) package.

### Code Generation

Some code in this project gets generated from different sources. Here is an overview of generated code:

* [**GoMock**](https://github.com/golang/mock): testing; generated at [internal/mocks](internal/mocks) from different
  interfaces in the project
* [**Wire**](https://github.com/google/wire): dependency injection; generated at [internal/wire](internal/wire) from the
  dependency injection code in the same package
* [**OAPI Codegen**](https://github.com/deepmap/oapi-codegen): REST API with strict types; generated
  at [internal/restserver/openapi.gen.go](internal/restserver/openapi.gen.go) from the OpenAPI spec
  at [.openapi/openapi.yaml](.openapi/openapi.yaml)
* [**SQLBoiler**](https://github.com/volatiletech/sqlboiler): per SQL database type structs for safe access; generated
  at [internal/db](internal/db) from the database schema. The database must be online and must have all migrations
  applied for generation. It uses the credentials in [.env](.env) to connect to the database.

### Testdata Generation

The server uses certificates for testing. The generation script and certificate specifications can be found in
[testdata/certificates](testdata/certificates). The certificates are generated
using [cfssl](https://github.com/cloudflare/cfssl).

### Setup

Execute the following commands to set up the development environment:

```sh
docker compose -f docker-compose.dev.yml up -d
make migrate-postgresql generate-all go-test
```

This will start the development containers, run the database migrations and generate code and testdata certificates.
It will also run the tests to verify that everything is working.