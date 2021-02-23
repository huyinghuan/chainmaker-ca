package handlers

import (
	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
)

//GenerateCert .
func GenerateCert(c *gin.Context) {
	var chainMakerCertApplyReq models.ChainMakerCertApplyReq
	if err := c.ShouldBind(&chainMakerCertApplyReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	filesource, err := services.GenerateChainMakerCert(&chainMakerCertApplyReq)
	if chainMakerCertApplyReq.Filetarget == "" {
		filesource = ""
	}
	if err != nil {
		msg := "Generate chainmaker cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	tarBytes, err := services.GetChainMakerCertTar("", filesource)
	if err != nil {
		msg := "Tar chainmaker cert file failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	filename := "chainmake-cert.tar.gz"
	SuccessfulFileRespFunc(filename, tarBytes, c)
}
