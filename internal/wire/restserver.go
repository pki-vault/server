//go:build wireinject
// +build wireinject

package wire

import (
	"github.com/gin-gonic/gin"
	"github.com/google/wire"
	"github.com/jonboulle/clockwork"
	"github.com/pki-vault/server/internal/db/repository"
	"github.com/pki-vault/server/internal/restserver"
)

func ProvideGinEngine(repositoryBundle repository.Bundle) (*gin.Engine, error) {
	wire.Build(
		restserver.InitializeGinEngine,
		restserver.NewRestHandlerImpl,
		repositorySet,
		InitializeZapLogger,
		servicesSet,
		clockwork.NewRealClock,
		wire.Bind(new(restserver.StrictServerInterface), new(*restserver.RestHandlerImpl)),
	)
	return new(gin.Engine), nil
}
