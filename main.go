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
	g.Run(":8080")
}
func testData() {
	var rootUser = &db.Customer{
		Name: "root",
	}
	var adminUser = &db.Customer{
		Name: "admin",
	}
	var org1User = &db.Customer{
		Name: "org1",
	}
	var org2User = &db.Customer{
		Name: "org2",
	}
	var userUser = &db.Customer{
		Name:     "user1",
		Password: "12345",
	}
	models.InsertCustomer(rootUser)
	models.InsertCustomer(adminUser)
	models.InsertCustomer(userUser)
	models.InsertCustomer(org1User)
	models.InsertCustomer(org2User)
}
