package handlers

import (
	"fmt"
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

//GenerateChainMakerCertFile /
func GenerateChainMakerCertFile(c *gin.Context) {
	var req models.GetTarCertFileReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	tarBytes, err := services.GetChainMakerCertTar(req.Filetarget)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate chainmaker cert file failed!",
			"error": err.Error(),
		})
		return
	}
	filename := "chainmake-cert.tar.gz"
	c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Writer.Header().Add("Content-Type", "application/octet-stream")
	c.Data(http.StatusOK, "application/octet-stream", tarBytes)
	return
}
