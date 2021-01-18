package main

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/routers"
	"chainmaker.org/wx-CRA-backend/services"
	"chainmaker.org/wx-CRA-backend/utils"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

func init() {
	utils.InitConfig()
	db.InitDB()
	services.InitServer()
	go services.InitRPCServer()
}
func main() {
	g := gin.New()
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
