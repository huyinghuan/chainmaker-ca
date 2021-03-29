package handlers

import (
	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"github.com/gin-gonic/gin"
)

//GeneratePrivateKey .
func GeneratePrivateKey(c *gin.Context) {
	var generateKeyPairReq models.GenerateKeyPairReq
	if err := c.ShouldBind(&generateKeyPairReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	var user db.KeyPairUser
	user.CertUsage = generateKeyPairReq.CertUsage
	user.UserType = generateKeyPairReq.UserType
	user.OrgID = generateKeyPairReq.OrgID
	user.UserID = generateKeyPairReq.UserID
	var isKms bool
	if utils.GetGenerateKeyPairType() && (user.UserType == db.USER_ADMIN || user.UserType == db.USER_USER) {
		isKms = true
	}
	_, keyID, err := services.CreateKeyPair(generateKeyPairReq.PrivateKeyType, generateKeyPairReq.HashType, &user, generateKeyPairReq.PrivateKeyPwd, isKms)
	if err != nil {
		msg := "Create key pair failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("", gin.H{"keyID": keyID}, c)
}

//ApplyCert 申请证书
func ApplyCert(c *gin.Context) {
	var applyCertReq models.ApplyCertReq
	if err := c.ShouldBind(&applyCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, err := services.ApplyCert(&applyCertReq)
	if err != nil {
		msg := "Apply cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "cert.crt"
	SuccessfulFileRespFunc(fileName, certContent, c)
}

//UpdateCert 更新证书
func UpdateCert(c *gin.Context) {
	var updateCertReq models.UpdateCertReq
	if err := c.ShouldBind(&updateCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	certContent, err := services.UpdateCert(&updateCertReq)
	if err != nil {
		msg := "Update cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "cert.crt"
	SuccessfulFileRespFunc(fileName, certContent, c)
}

//RevokedCert 撤销证书
func RevokedCert(c *gin.Context) {
	var revokedCertReq models.RevokedCertReq
	if err := c.ShouldBind(&revokedCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	err := services.RevokedCert(&revokedCertReq)
	if err != nil {
		msg := "Revoked cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("Revoked cert successfully", "", c)
}

//RevokedCert 撤销证书
func RevokedCertWithCRL(c *gin.Context) {
	var revokedCertReq models.RevokedCertReq
	if err := c.ShouldBind(&revokedCertReq); err != nil {
		msg := "Parameter input error"
		FailedRespFunc(msg, "", c)
		return
	}
	revokedCertListBytes, err := services.RevokedCertWithCRL(&revokedCertReq)
	if err != nil {
		msg := "Revoked cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	fileName := "RevocationList.crl"
	SuccessfulJSONRespFunc(fileName, revokedCertListBytes, c)
}
