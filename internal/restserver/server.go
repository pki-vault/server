package restserver

import (
	"fmt"
	middleware "github.com/deepmap/oapi-codegen/pkg/gin-middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func InitializeGinEngine(
	logger *zap.Logger,
	handler StrictServerInterface,
) (*gin.Engine, error) {
	engine := gin.New()

	swagger, err := GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("unable to load swagger spec: %w", err)
	}

	RegisterHandlersWithOptions(engine, NewStrictHandler(handler, []StrictMiddlewareFunc{}), GinServerOptions{
		Middlewares: []MiddlewareFunc{
			MiddlewareFunc(LoggerMiddleware(logger)),
			MiddlewareFunc(middleware.OapiRequestValidator(swagger)),
		},
		ErrorHandler: nil,
	})

	return engine, nil
}
