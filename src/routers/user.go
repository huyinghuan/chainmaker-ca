package routers

import (
	"chainmaker.org/chainmaker-ca-backend/src/handlers"
	"github.com/gin-gonic/gin"
)

//LoadUserRouter 加载路由
func LoadUserRouter(e *gin.Engine) {
	e.POST("/api/ca/gencertbycsr", handlers.GenerateCertByCsr)
	e.POST("/api/ca/gencert", handlers.GenCert)
	e.POST("/api/ca/querycert", handlers.QueryCert) //查询请求
	e.POST("/api/ca/updatecert", handlers.UpdateCert)
	e.POST("/api/ca/revokedcert", handlers.RevokedCert)
	e.POST("/api/ca/crllist", handlers.CrlList)
}
