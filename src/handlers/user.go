package handlers

import (
	"strconv"

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

func CertInfo(c *gin.Context) {
	certId := c.Query("Id")
	if certId == "" {
		msg := "input parameter error"
		FailedRespFunc(msg, "", c)
		return
	}
	valInt, err := strconv.Atoi(certId) // 函数原型 ：func Atoi(s string) (int, error)
	if err != nil {
		msg := "convert string to int failed"
		FailedRespFunc(msg, "", c)
		return
	}

	certInfo, err := services.CertInfo(valInt)
	if err != nil {
		msg := "Revoked cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("", certInfo, c)
}

func Download(c *gin.Context) {
	certSN := c.Query("CertSN")
	if certSN == "" {
		msg := "input parameter error"
		FailedRespFunc(msg, "", c)
		return
	}
	fileName := "cert.key"
	keyOrTLs := c.Query("type")
	if keyOrTLs == "" {
		keyOrTLs = "cert"
		fileName = "cert.crt"
	}

	valInt, err := strconv.ParseInt(certSN, 10, 64)
	if err != nil {
		msg := "convert string to int failed"
		FailedRespFunc(msg, "", c)
		return
	}

	certInfo, err := services.Download(valInt, keyOrTLs)
	if err != nil {
		msg := "Revoked cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulFileRespFunc(fileName, certInfo, c)
}

func Freeze(c *gin.Context) {
	certSN := c.Query("CertSN")
	if certSN == "" {
		msg := "input parameter error"
		FailedRespFunc(msg, "", c)
		return
	}
	valInt, err := strconv.ParseInt(certSN, 10, 64)
	if err != nil {
		msg := "convert string to int failed"
		FailedRespFunc(msg, "", c)
		return
	}

	err = services.Freeze(valInt)
	if err != nil {
		msg := "Freeze cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("", "", c)
}

func UnFreeze(c *gin.Context) {
	certSN := c.Query("CertSN")
	if certSN == "" {
		msg := "input parameter error"
		FailedRespFunc(msg, "", c)
		return
	}
	valInt, err := strconv.ParseInt(certSN, 10, 64)
	if err != nil {
		msg := "convert string to int failed"
		FailedRespFunc(msg, "", c)
		return
	}

	err = services.UnFreeze(valInt)
	if err != nil {
		msg := "unFreeze cert failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("", "", c)
}

func CertList(c *gin.Context) {
	var getCertsReq models.GetCertsReq
	if err := c.ShouldBind(&getCertsReq); err != nil {
		// msg := "input parameter error"
		FailedRespFunc(err.Error(), "", c)
		return
	}

	certs, err := services.CertList(&getCertsReq)
	if err != nil {
		msg := "get certs failed"
		FailedRespFunc(msg, err.Error(), c)
		return
	}
	SuccessfulJSONRespFunc("get certs successfully", certs, c)
}
