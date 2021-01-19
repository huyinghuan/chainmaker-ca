package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//InitRootCA 初始化根CA
func InitRootCA() {
	//读配置文件（可以升级为web传参）
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Get Root Ca Config Failed!", zap.Error(err))
		return
	}
	var user db.KeyPairUser
	user.CertUsage = db.SIGN
	user.UserType = db.ROOT_CA
	user.OrgID = "wx-root"
	//生成公私钥
	privKey, keyID, err := CreateKeyPair(user, rootCaConfig.PrivateKeyPwd)
	if err != nil {
		logger.Error("Create key pair to db  Failed!", zap.Error(err))
		return
	}
	//写私钥
	keyPair, err := models.GetKeyPairByID(keyID)
	if err != nil {
		logger.Error("Get key pair from db  Failed!", zap.Error(err))
		return
	}
	err = WritePrivKeyFile(rootCaConfig.PrivateKeyPath, keyPair.PrivateKey)
	if err != nil {
		logger.Error("Wirte root key pair  Failed!", zap.Error(err))
		return
	}
	//构建证书结构体
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	O := DefaultRootOrg
	OU := "ca.root"
	CN := OU + "." + O
	certModel, err := createCACert(privKey, hashType,
		rootCaConfig.Country, rootCaConfig.Locality, rootCaConfig.Province, OU,
		O, CN, rootCaConfig.ExpireYear, nil)
	if err != nil {
		logger.Error("Create CA certificate failed!", zap.Error(err))
		return
	}
	if err != nil {
		logger.Error("Get customer id by name failed!", zap.Error(err))
		return
	}
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = keyID
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
	if err := WirteCertToFile(rootCaConfig.CertPath, certContent); err != nil {
		logger.Error("Write cert file failed!", zap.Error(err))
		return
	}
}

//CreateCACert 创建入库的证书结构
func createCACert(privKey crypto.PrivateKey, hashType crypto.HashType,
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
	certModel.IsCa = true
	certModel.SerialNumber = template.SerialNumber.Int64()
	certModel.Signature = hex.EncodeToString(template.Signature)
	certModel.HashType = hashType
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
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	return &certModel, nil
}
