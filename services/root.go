package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger

//InitRootCA 初始化根CA
func InitRootCA() {
	logger = loggers.GetLogger()
	//读配置文件（可以升级为web传参）
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Get Root Ca Config Failed!", zap.Error(err))
		return
	}
	//生成公私钥
	privKey, err := CreateKeyPairToDB(&rootCaConfig)
	if err != nil {
		logger.Error("Create key pair to db  Failed!", zap.Error(err))
		return
	}
	//构建证书结构体
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	certModel, err := CreateCACert(privKey, hashType,
		rootCaConfig.Country, rootCaConfig.Locality, rootCaConfig.Province, rootCaConfig.OrganizationalUnit,
		rootCaConfig.Organization, rootCaConfig.CommonName, rootCaConfig.ExpireYear, []string{})
	if err != nil {
		logger.Error("Create CA certificate failed!", zap.Error(err))
		return
	}
	certModel.CustomerID, err = models.GetCustomerIDByName(rootCaConfig.Username)
	if err != nil {
		logger.Error("Get customer id by name failed!", zap.Error(err))
		return
	}

	//证书入库
	if err := models.InsertCert(certModel); err != nil {
		logger.Error("Insert cert to db failed!", zap.Error(err))
		return
	}

	//证书写入文件（也可以是传到浏览器提供下载）
	certContent, err := hex.DecodeString(certModel.CertEncode)
	if err != nil {
		logger.Error("hex decode failed!", zap.Error(err))
		return
	}
	if err := WirteCertToFile(rootCaConfig.CertPath, rootCaConfig.CertName, certContent); err != nil {
		logger.Error("Write cert file failed!", zap.Error(err))
		return
	}
}

//CreateCACert 创建入库的证书结构
func CreateCACert(privKey crypto.PrivateKey, hashType crypto.HashType,
	country, locality, province, organizationalUnit, organization, commonName string,
	expireYear int32, sans []string) (*db.Cert, error) {
	var certModel db.Cert
	template, err := cert.GenerateCertTemplate(privKey, true, country, locality, province, organizationalUnit, organization, commonName, expireYear, sans)
	if err != nil {
		return nil, fmt.Errorf("generateCertTemplate failed, %s", err.Error())
	}

	template.SubjectKeyId, err = cert.ComputeSKI(hashType, privKey.PublicKey().ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("create CA cert compute SKI failed, %s", err.Error())
	}
	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, template,
		privKey.PublicKey().ToStandardKey(), privKey.ToStandardKey())
	if err != nil {
		return nil, err
	}
	certModel.SerialNumber = template.SerialNumber.Int64()
	certModel.Signature = hex.EncodeToString(template.Signature)
	certModel.HashTyep = hashType
	certModel.IssueDate = template.NotBefore.Unix()
	certModel.InvalidDate = template.NotAfter.Unix()
	certModel.CertEncode = hex.EncodeToString(x509certEncode)
	certModel.Country = country
	certModel.ExpireYear = expireYear
	certModel.Locality = locality
	certModel.Province = province
	certModel.Organization = organization
	certModel.OrganizationalUnit = organizationalUnit
	certModel.CommonName = commonName
	certModel.CertType = db.ROOT_CA
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	return &certModel, nil
}
