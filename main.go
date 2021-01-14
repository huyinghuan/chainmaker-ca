package main

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/models"
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
	testData()
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
	services.InitRPCServer()
	g.Run(":8090")
}
func testData() {
	var org1User = &db.User{
		Name: "admin",
	}
	var org2User = &db.User{
		Name: "admin",
	}
	var org3User = &db.User{
		Name: "admin",
	}
	var org4User = &db.User{
		Name: "admin",
	}
	models.InsertUser(org1User)
	models.InsertUser(org2User)
	models.InsertUser(org3User)
	models.InsertUser(org4User)
}
