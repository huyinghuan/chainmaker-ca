package routers

import (
	"chainmaker.org/wx-CRA-backend/handlers"
	"github.com/gin-gonic/gin"
)

//LoadUserRouter 加载路由
func LoadUserRouter(e *gin.Engine) {
	e.POST("/api/login", handlers.LoginHandle)
	e.POST("/api/generateprivkey", handlers.JWTAuthMiddleware(), handlers.GeneratePrivateKey)
	e.POST("/api/applycert", handlers.JWTAuthMiddleware(), handlers.ApplyCert)
	e.POST("/api/updatecert", handlers.JWTAuthMiddleware(), handlers.UpdateCert)
	e.POST("/api/revokedcert", handlers.JWTAuthMiddleware())
}
