/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"net/http"

	"chainmaker.org/chainmaker-ca-backend/src/handlers"
	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/routers"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"github.com/gin-gonic/gin"
)

func init() {
	utils.SetConfig(utils.GetConfigEnv())
	db.DBInit()
	services.InitServer()
}

func main() {
	isUseJwt, err := services.InitAccessControl()
	if err != nil {
		panic(err)
	}
	g := gin.New()
	//loading middleware
	g.Use(loggers.GinLogger(), loggers.GinRecovery(true))
	g.Use(handlers.Cors())
	g.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"msg":  handlers.SUCCESS_MSG,
			"data": "Hello,World!",
		})
	})
	//loading route
	routers.LoadLoginRouter(g)
	if isUseJwt {
		g.Use(handlers.JWTAuthMiddleware())
	}
	routers.LoadCAServerRouter(g)
	serverPort := services.ServerPortFromConfig()
	err = g.Run(serverPort)
	if err != nil {
		err := fmt.Errorf("gin server start failed: %s", err.Error())
		panic(err)
	}
}
