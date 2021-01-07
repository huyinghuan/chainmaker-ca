package handlers

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/services"
	"github.com/gin-gonic/gin"
)

//GeneratePrivateKey .
func GeneratePrivateKey(c *gin.Context) {
	username := c.MustGet("username").(string)
	_, err := services.CreateUserKeyPair(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "generate privatekey failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "generate private key successfully!",
	})
	return
}

//ApplyCert 申请证书
func ApplyCert(c *gin.Context) {
	username := c.MustGet("username").(string)
	var applyCertReq models.ApplyCertReq
	if err := c.ShouldBind(&applyCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	certContent, err := services.ApplyCert(&applyCertReq, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Apply user cert failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Apply user cert successfully!",
		"data": certContent,
	})
	return
}

//UpdateCert 更新证书
func UpdateCert(c *gin.Context) {
	username := c.MustGet("username").(string)
	var updateCertReq models.UpdateCertReq
	if err := c.ShouldBind(&updateCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	certContent, err := services.UpdateCert(&updateCertReq, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Update user cert failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Update user cert successfully!",
		"data": certContent,
	})
	return
}
