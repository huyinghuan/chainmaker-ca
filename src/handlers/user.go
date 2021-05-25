package handlers

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
)

//通过CSR流文件申请证书

func GenerateCertByCsr(c *gin.Context) {
	var generateCertByCsrReq models.GenerateCertByCsrReq
	//从新更改从前端拿数据的模式，这里是先通过表单拿到id类数据，再通过文件上传形式拿到csr流文件
	generateCertByCsrReq.OrgID = c.PostForm("OrgID")
	generateCertByCsrReq.UserID = c.PostForm("UserID")
	generateCertByCsrReq.UserType = c.PostForm("UserType")
	generateCertByCsrReq.CertUsage = c.PostForm("CertUsage")
	//单独读取上传文件，读出csr流文件
	upLoadFile, err := c.FormFile("CsrFile")
	if err != nil {
		msg := err.Error()
		FailedRespFunc(msg, "", c)
		return
	}
	file, err := upLoadFile.Open()
	if err != nil {
		fmt.Print("open file failed")
	}
	generateCertByCsrReq.CsrBytes, err = services.ReadWithFile(file)
	if err != nil {
		msg := "Generate Cert By Csr failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	certContent, err := services.GenerateCertByCsr(&generateCertByCsrReq)
	if err != nil {
		msg := "Generate Cert By Csr failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "cert.crt"
	SuccessfulFileRespFunc(fileName, certContent, c)
}

func GenCert(c *gin.Context) {
	var genCertReq models.GenCertReq
	if err := c.ShouldBind(&genCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, privateKey, err := services.GenCert(&genCertReq)
	if err != nil {
		msg := "Gen Cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	content, err := services.ZipCertAndPrivateKey(certContent, privateKey)
	if err != nil {
		msg := "Gen Cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulFileRespFunc("cert&privateKey.zip", content, c)
}

func QueryCert(c *gin.Context) {
	var querycertReq models.QueryCertReq
	if err := c.ShouldBind(&querycertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, err := services.QueryCert(&querycertReq)
	if err != nil {
		msg := "Query Cert error"
		FailedRespFunc(msg, "", c)
		return
	}
	SuccessfulFileRespFunc("cert.crt", certContent, c)
}

func UpdateCert(c *gin.Context) {
	var updatecertReq models.UpdateCertReq
	if err := c.ShouldBind(&updatecertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, err := services.UpdateCert(&updatecertReq)
	if err != nil {
		msg := "Update Cert error"
		FailedRespFunc(msg, "", c)
		return
	}
	SuccessfulFileRespFunc("cert.crt", certContent, c)
}
