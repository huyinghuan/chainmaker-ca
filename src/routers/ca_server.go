package routers

import (
	"chainmaker.org/chainmaker-ca-backend/src/handlers"
	"github.com/gin-gonic/gin"
)

const ROUTERS_HEADER = "/api/ca"

func LoadCAServerRouter(e *gin.Engine) {
	e.POST(ROUTERS_HEADER+"/gencertbycsr", handlers.GenerateCertByCsr())
	e.POST(ROUTERS_HEADER+"/gencert", handlers.GenCert())
	e.POST(ROUTERS_HEADER+"/querycert", handlers.QueryCert())
	e.POST(ROUTERS_HEADER+"/querycertbystatus", handlers.QueryCertByStatus())
	e.POST(ROUTERS_HEADER+"/updatecert", handlers.UpdateCert())
	e.POST(ROUTERS_HEADER+"/revokedcert", handlers.RevokedCert())
	e.POST(ROUTERS_HEADER+"/crllist", handlers.CrlList())
	e.POST(ROUTERS_HEADER+"/createcsr", handlers.CreateCsr())
}
