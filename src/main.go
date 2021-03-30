package main

import (
	"net/http"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/routers"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

func init() {
	utils.SetConfig(utils.GetConfigEnv())
	db.InitDB()
	services.InitServer()
	go services.InitRPCServer()
}
func main() {
	g := gin.New()
	g.Use(utils.Cors())
	g.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"msg":   "Hello,World!",
			"error": "",
			"data":  "test!",
		})
	})
	//加载中间件
	g.Use(loggers.GinLogger(), loggers.GinRecovery(true))
	//加载路由
	routers.LoadUserRouter(g)
	routers.LoadChainMakerRouters(g)
	g.Run(":8090")
}
