package handlers

import (
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/services"
	"chainmaker.org/wx-CRA-backend/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

//GeneratePrivateKey .
func GeneratePrivateKey(c *gin.Context) {
	username := c.MustGet("username").(string)

	//生成私钥
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]
	privKey, err := services.CreatePrivKey(keyType)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Generate private key failed!",
			"error": err.Error(),
		})
		return
	}
	privKeyBytes, _ := privKey.Bytes()
	var customer db.Customer
	customer.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATEKEY", Bytes: privKeyBytes})
	customer.PublicKey, _ = privKey.PublicKey().Bytes()
	err = models.UpdateCustomerByName(username, customer)
	if err != nil {
		logger.Error("update customer failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "update customer failed!",
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "generate private key successfully!",
	})
	return
}

//ApplyCert 申请证书
func ApplyCert(c *gin.Context) {
	logger = loggers.GetLogger()
	username := c.MustGet("username").(string)
	var applyCertReq models.ApplyCertReq
	if err := c.ShouldBind(&applyCertReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 400,
			"msg":  "Bad request!",
		})
		return
	}
	customer, err := models.GetCustomerByName(username)
	if err != nil {
		logger.Error("get customer failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":   500,
			"msg":    "get customer failed!",
			"error:": err.Error(),
		})
	}
	privateKeyBytes := customer.PrivateKey
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		logger.Error("private from der failed!", zap.Error(err))
		c.JSON(http.StatusOK, gin.H{
			"code":  500,
			"msg":   "private from der failed!",
			"error": err.Error(),
		})
	}
	certCSR, err := services.CreateCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
		applyCertReq.OrganizationalUnit, applyCertReq.Organization, applyCertReq.CommonName)
	if err != nil {
		logger.Error("create csr failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "create csr failed!",
			"error": err.Error(),
		})
		return
	}
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Read private key file failed!",
			"error": err.Error(),
		})
		return
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	privateKeyPwd := services.DefaultPrivateKeyPwd + utils.GetIntermCAPrivateKeyPwd()
	issureHashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		logger.Error("Get issuer private key pwd hash failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Get issuer private key pwd hash failed!",
			"error": err.Error(),
		})
		return
	}
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, issureHashPwd)
	if err != nil {
		logger.Error("PrivateKey Decrypt  failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "PrivateKey Decrypt  failed!",
			"error": err.Error(),
		})
		return
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Read cert file failed!",
			"error": err.Error(),
		})
		return
	}
	certModel, err := services.IssueCertificate(hashType, false, issuerPrivKey, certCSR, certBytes, applyCertReq.ExpireYear, []string{}, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"msg":   "Issue Cert failed!",
			"error": err.Error(),
		})
		return
	}
	certModel.CustomerID = customer.ID
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "Apply user cert successfully!",
	})
	return
}
