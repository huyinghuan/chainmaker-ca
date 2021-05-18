package main

import (
	"net/http"

	"chainmaker.org/chainmaker-ca-backend/src/handlers"
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
	db.DBInit()
	services.InitServer()
	go services.InitRPCServer()
}
func main() {
	g := gin.New()
	//loading middleware
	g.Use(loggers.GinLogger(), loggers.GinRecovery(true))
	g.Use(handlers.Cors())
	//test route
	g.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"msg":   "Hello,World!",
			"error": "",
			"data":  "test!",
		})
	})
	//loading route
	routers.LoadUserRouter(g)
	routers.LoadChainMakerRouters(g)
	g.Run(":8090")
}
