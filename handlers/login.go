package handlers

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/models"
	"github.com/gin-gonic/gin"
)

//UserInfo userinfo
type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//LoginHandle .
func LoginHandle(c *gin.Context) {
	var user UserInfo
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	User, err := models.UserByNamePwd(user.Username, user.Password)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  500,
			"msg":   "Get User failed!",
			"error": err.Error(),
		})
		return
	}
	if User == nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 202,
			"msg":  "User does not exist! ",
		})
		return
	}
	tokenString, err := GenerateToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate token failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Login successfully!",
		"data": gin.H{
			"token": tokenString,
		},
	})
}
