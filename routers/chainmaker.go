package routers

import "github.com/gin-gonic/gin"

//LoadChainMakerRouters 加载chainmaker路由
func LoadChainMakerRouters(e *gin.Engine) {
	e.POST("chainmaker/generatecert")
	e.GET("chainmaker/getcert")
}
