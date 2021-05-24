package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
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
	var genCertReq models.GenCertReq
	if err := c.ShouldBind(&genCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, privateKey, err := services.GenCert(&genCertReq)
	//这里可以拿到私钥，分别存两个文件后，压缩打包
	//未完成，待写
	if err != nil {
		msg := "Gen Cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "cert&privateKey.zip"
	file, err := os.Create(utils.DefaultWorkDirectory + fileName)
	if err != nil {
		msg := "create file failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	f, err := writer.Create("cert.crt")
	if err != nil {
		msg := "compress file failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	f.Write(certContent)
	f, err = writer.Create("privateKey.key")
	if err != nil {
		msg := "compress file failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	f.Write(privateKey)
	writer.Close()
	content, err := ioutil.ReadFile(utils.DefaultWorkDirectory + fileName)
	if err != nil {
		msg := "read file failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulFileRespFunc(fileName, content, c)
}
