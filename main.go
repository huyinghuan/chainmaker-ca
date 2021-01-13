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
func testData() {
	var org1User = &db.Customer{
		Name: "admin",
	}
	var org2User = &db.Customer{
		Name: "admin",
	}
	var org3User = &db.Customer{
		Name: "admin",
	}
	var org4User = &db.Customer{
		Name: "admin",
	}
	models.InsertCustomer(org1User)
	models.InsertCustomer(org2User)
	models.InsertCustomer(org3User)
	models.InsertCustomer(org4User)
}
