package restserver

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var GinCtxLoggerKey = "ginCtxLoggerKey"

func LoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(GinCtxLoggerKey, logger.With(zap.String("remote-ip", c.ClientIP())))
		c.Next()
	}
}
