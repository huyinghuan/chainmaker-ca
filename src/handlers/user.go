package handlers

import (
	"fmt"
	"io"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
)

//通过CSR流文件申请证书

func GenerateCertByCsr(c *gin.Context) {
	var generateCertByCsrReq models.GenerateCertByCsrReq
	//从新更改从前端拿数据的模式，这里是先通过表单拿到id类数据，再通过文件上传形式拿到csr流文件
	generateCertByCsrReq.OrgID = c.PostForm("OrgID")
	generateCertByCsrReq.UserID = c.PostForm("UserID")
	var ok bool
	generateCertByCsrReq.UserType, ok = db.Name2UserTypeMap[c.PostForm("UserType")]
	if !ok {
		msg := "UserType input error"
		FailedRespFunc(msg, "", c)
		return
	}
	generateCertByCsrReq.CertUsage, ok = db.Name2CertUsageMap[c.PostForm("CertUsage")]
	if !ok {
		msg := "CertUsage input error"
		FailedRespFunc(msg, "", c)
		return
	}
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
	var tmp = make([]byte, 128)
	for {
		n, err := file.Read(tmp)
		if err == io.EOF {
			break
		}
		if err != nil {
			msg := err.Error()
			FailedRespFunc(msg, "", c)
			return
		}
		generateCertByCsrReq.CsrBytes = append(generateCertByCsrReq.CsrBytes, tmp[:n]...)
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
	var genCertReq models.GenCert
	if err := c.ShouldBind(&genCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, err := services.GenCert(&genCertReq)
	if err != nil {
		msg := "Gen Cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "cert.crt"
	SuccessfulFileRespFunc(fileName, certContent, c)
}
