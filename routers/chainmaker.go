package routers

import (
	"chainmaker.org/wx-CRA-backend/handlers"

	"github.com/gin-gonic/gin"
)

//LoadChainMakerRouters 加载chainmaker路由
func LoadChainMakerRouters(e *gin.Engine) {
	e.POST("chainmaker/generatecert", handlers.GenerateCert)
	e.GET("chainmaker/getcert")
}
