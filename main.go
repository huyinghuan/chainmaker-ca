package main

import (
	"fmt"
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
	var user db.Customer
	user.Name = "user1"
	user.Password = "12345"
	user.CustomerType = "user"
	err := models.InsertCustomer(&user)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
	}
	//加载中间件
	g.Use(loggers.GinLogger(), loggers.GinRecovery(true))
	//加载路由
	routers.LoadUserRouter(g)
	g.Run(":8080")
}
