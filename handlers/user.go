package handlers

import (
	"net/http"

	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/services"
	"chainmaker.org/wx-CRA-backend/utils"
	"github.com/gin-gonic/gin"
)

//GeneratePrivateKey .
func GeneratePrivateKey(c *gin.Context) {
	var generateKeyPairReq models.GenerateKeyPairReq
	if err := c.ShouldBind(&generateKeyPairReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
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
	privateKey, keyID, err := services.CreateKeyPair(&user, generateKeyPairReq.PrivateKeyPwd, isKms)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate privatekey failed!",
			"error": err.Error(),
		})
		return
	}
	privateKeyStr, _ := privateKey.String()
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg": gin.H{
			"keyID": keyID,
			"key":   privateKeyStr,
		},
	})
	return
}

//ApplyCert 申请证书
func ApplyCert(c *gin.Context) {
	var applyCertReq models.ApplyCertReq
	if err := c.ShouldBind(&applyCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	certContent, err := services.ApplyCert(&applyCertReq)
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
	var updateCertReq models.UpdateCertReq
	if err := c.ShouldBind(&updateCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	certContent, err := services.UpdateCert(&updateCertReq)
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

//RevokedCert 撤销证书
func RevokedCert(c *gin.Context) {
	var revokedCertReq models.RevokedCertReq
	if err := c.ShouldBind(&revokedCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	err := services.RevokedCert(&revokedCertReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Revoked Cert failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Revoked Cert successfully!",
	})
	return
}

//GetRevokedCertList .
func GetRevokedCertList(c *gin.Context) {
	revokedCertListBytes, err := services.GetRevokedCertList()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Get revoked cert list failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Get revoked cert list successfully!",
		"data": revokedCertListBytes,
	})
	return
}
