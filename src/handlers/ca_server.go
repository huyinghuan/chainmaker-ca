package handlers

import (
	"encoding/base64"
	"encoding/pem"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
)

func GenerateCertByCsr() gin.HandlerFunc {
	return func(c *gin.Context) {
		var generateCertByCsrReq models.GenerateCertByCsrReq
		//从新更改从前端拿数据的模式，这里是先通过表单拿到id类数据，再通过文件上传形式拿到csr流文件
		generateCertByCsrReq.OrgID = c.PostForm("orgId")
		generateCertByCsrReq.UserID = c.PostForm("userId")
		generateCertByCsrReq.UserType = c.PostForm("userType")
		generateCertByCsrReq.CertUsage = c.PostForm("certUsage")
		//单独读取上传文件，读出csr流文件
		upLoadFile, err := c.FormFile("csrFile")
		if err != nil {
			msg := "generate cert by csr failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		file, err := upLoadFile.Open()
		if err != nil {
			msg := "generate cert by csr failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		defer file.Close()
		generateCertByCsrReq.CsrBytes, err = services.ReadWithFile(file)
		if err != nil {
			msg := "generate cert by csr failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		certContent, err := services.GenerateCertByCsr(&generateCertByCsrReq)
		if err != nil {
			msg := "generate cert by csr failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContent, c)
	}
}

func GenCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var genCertReq models.GenCertReq
		if err := c.ShouldBind(&genCertReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		certContentAndPrivateKey, err := services.GenCert(&genCertReq)
		if err != nil {
			msg := "generate cert failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContentAndPrivateKey, c)
	}
}

func QueryCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertReq models.QueryCertReq
		if err := c.ShouldBind(&queryCertReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		queryCertResp, err := services.QueryCert(&queryCertReq)
		if err != nil {
			msg := "query certs failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		SuccessfulJSONResp("", queryCertResp, c)
	}
}

func QueryCertByStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertByStatusReq models.QueryCertByStatusReq
		if err := c.ShouldBind(&queryCertByStatusReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		queryCertRespList, err := services.QueryCertByStatus(&queryCertByStatusReq)
		if err != nil {
			msg := "query certs by status failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		SuccessfulJSONResp("", queryCertRespList, c)
	}
}

func UpdateCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var updatecertReq models.UpdateCertReq
		if err := c.ShouldBind(&updatecertReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		certContent, err := services.UpdateCert(&updatecertReq)
		if err != nil {
			msg := "update cert failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContent, c)
	}
}

func RevokedCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var revokedCertReq models.RevokedCertReq
		if err := c.ShouldBind(&revokedCertReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		crlList, err := services.RevokedCert(&revokedCertReq)
		if err != nil {
			msg := " revoked cert failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}

		crlList = pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlList})
		reCrlList := base64.StdEncoding.EncodeToString(crlList)
		SuccessfulJSONResp("", reCrlList, c)
	}
}

func CrlList() gin.HandlerFunc {
	return func(c *gin.Context) {
		var crlListReq models.CrlListReq
		if err := c.ShouldBind(&crlListReq); err != nil {
			msg := "parameters input error"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		crlList, err := services.CrlList(&crlListReq)
		if err != nil {
			msg := "CrlList get failed"
			FailedJSONResp(msg, err.Error(), c)
			return
		}
		crlList = pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlList})
		reCrlList := base64.StdEncoding.EncodeToString(crlList)
		SuccessfulJSONResp("", reCrlList, c)
	}
}
