package handlers

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/services"
	"github.com/gin-gonic/gin"
)

//GenerateCert .
func GenerateCert(c *gin.Context) {
	var chainMakerCertApplyReq models.ChainMakerCertApplyReq
	if err := c.ShouldBind(&chainMakerCertApplyReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	err := services.GenerateChainMakerCert(&chainMakerCertApplyReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate chainmaker cert failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Generate chainmaker cert successfully!",
	})
	return
}
