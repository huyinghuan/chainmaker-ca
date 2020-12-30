package services

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

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
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Get Root Ca Config Failed!", zap.Error(err))
		return
	}
	var keyType crypto.KeyType
	//生成公私要钥
	for i, v := range crypto.KeyType2NameMap {
		if v == rootCaConfig.PrivateKeyType {
			keyType = i
			break
		}
	}
	privKey, err := cert.CreatePrivKey(keyType, rootCaConfig.PrivateKeyPath, rootCaConfig.PrivateKeyName)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
		return
	}
	hashType := crypto.HashAlgoMap[rootCaConfig.HashType]
	certModel, err := CreateCACert(privKey, hashType, rootCaConfig.CertPath, rootCaConfig.CertName,
		rootCaConfig.Country, rootCaConfig.Locality, rootCaConfig.Province, rootCaConfig.OrganizationalUnit,
		rootCaConfig.Organization, rootCaConfig.CommonName, rootCaConfig.ExpireYear, []string{})
	if err != nil {
		logger.Error("Create CA certificate failed!", zap.Error(err))
	}
	if err := models.InsertCert(certModel); err != nil {
		logger.Error("Insert cert to db failed!", zap.Error(err))
	}
}

//CreateCACert 创建入库的证书结构
func CreateCACert(privKey crypto.PrivateKey, hashType crypto.HashType, certPath, certFileName string,
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
	if err = os.MkdirAll(certPath, os.ModePerm); err != nil {
		return nil, fmt.Errorf("mk cert dir failed, %s", err.Error())
	}

	f, err := os.Create(filepath.Join(certPath, certFileName))
	if err != nil {
		return nil, fmt.Errorf("create file failed, %s", err.Error())
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	certModel.Name = certFileName
	for i, v := range crypto.HashAlgoMap {
		if v == hashType {
			certModel.HashTyep = i
			break
		}
	}
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
