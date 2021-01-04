package handlers

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/models"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var logger *zap.Logger

//UserInfo userinfo
type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//LoginHandle .
func LoginHandle(c *gin.Context) {
	var user UserInfo
	logger = loggers.GetLogger()
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 201,
			"msg":  "登录失败",
		})
		return
	}
	customer, err := models.CustomerByNamePwd(user.Username, user.Password)
	if err != nil {
		logger.Error("Get customer failed!", zap.Error(err))
		c.JSON(http.StatusOK, gin.H{
			"code":  500,
			"msg":   "Get customer failed!",
			"error": err.Error(),
		})
		return
	}
	if customer == nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 202,
			"msg":  "用户不存在",
		})
		return
	}
	tokenString, err := GenerateToken(user.Username)
	if err != nil {
		logger.Error("Generate token failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate token failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "success",
		"data": gin.H{
			"token": tokenString,
		},
	})
}
