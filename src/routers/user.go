package routers

import (
	"chainmaker.org/chainmaker-ca-backend/src/handlers"
	"github.com/gin-gonic/gin"
)

//LoadUserRouter 加载路由
func LoadUserRouter(e *gin.Engine) {
	e.POST("/api/generateprivkey", handlers.GeneratePrivateKey)
	e.POST("/api/applycert", handlers.ApplyCert)
	e.POST("/api/certlist", handlers.CertList)
	e.GET("/api/certinfo", handlers.CertInfo)
	e.POST("/api/userApply", handlers.UserApplyCert)

	e.POST("/api/updatecert", handlers.UpdateCert)
	e.POST("/api/revokedcert", handlers.RevokedCert)
	e.POST("/api/revokedcertWithCRL", handlers.RevokedCertWithCRL)

	e.POST("/api/download", handlers.Download)
	e.POST("/api/freezecert", handlers.Freeze)
	e.POST("/api/unfreezecert", handlers.UnFreeze)
}
