package services

import (
	"encoding/hex"
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//CreateIntermediariesCert 签发中间机构证书
func CreateIntermediariesCert() {
	inmediaCaConfig, err := utils.GetIntermediaries()
	if err != nil {
		logger.Error("Get Intermediaries CA config failed!", zap.Error(err))
		return
	}
	//创建中间Ca用户
	var intermediaiesCustomer db.Customer
	intermediaiesCustomer.Name = "admin"
	intermediaiesCustomer.CustomerType = "intermediaies"
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	privKey, err := CreatePrivKey(keyType)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
		return
	}
	//私钥加密
	//私钥加密 密码:程序变量+读取密码
	privKeyPwd := DefaultPrivateKeyPwd + inmediaCaConfig.PrivateKeyPwd
	hashPwd, err := hash.Get(hashType, []byte(privKeyPwd))
	if err != nil {
		logger.Error("Get private key pwd hash failed!", zap.Error(err))
		return
	}
	//私钥加密
	privKeyPemBytes, err := EncryptPrivKey(privKey, hashPwd)
	if err != nil {
		logger.Error("Private Encrypt failed!", zap.Error(err))
		return
	}
	//将加密后私钥写入文件
	err = WritePrivKeyFile(inmediaCaConfig.PrivateKeyPath, privKeyPemBytes)
	if err != nil {
		logger.Error("Write privatekey failed!", zap.Error(err))
		return
	}
	//私钥入库
	intermediaiesCustomer.PrivateKey = privKeyPemBytes
	intermediaiesCustomer.PrivateKeyPwd = hex.EncodeToString(hashPwd)
	intermediaiesCustomer.PublicKey, _ = privKey.PublicKey().Bytes()
	err = models.InsertCustomer(&intermediaiesCustomer)
	if err != nil {
		logger.Error("Insert intermediaies customer failed!", zap.Error(err))
		return
	}
	//生成CSR 不以文件形式存在，在内存和数据库中
	csrBytes, err := CreateCSR(privKey, inmediaCaConfig.Country, inmediaCaConfig.Locality, inmediaCaConfig.Province, inmediaCaConfig.OrganizationalUnit,
		inmediaCaConfig.Organization, inmediaCaConfig.CommonName)
	if err != nil {
		logger.Error("Create CSR failed!", zap.Error(err))
		return
	}
	//读取签发者私钥（文件或者web端形式）
	issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return
	}
	//私钥解密
	privateKeyPwd := DefaultPrivateKeyPwd + utils.GetRootCaPrivateKeyPwd()
	issureHashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		logger.Error("Get issuer private key pwd hash failed!", zap.Error(err))
		return
	}
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, issureHashPwd)
	if err != nil {
		logger.Error("PrivateKey Decrypt  failed!", zap.Error(err))
		return
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return
	}
	certModel, err := IssueCertificate(hashType, true, issuerPrivKey, csrBytes, certBytes, inmediaCaConfig.ExpireYear, []string{}, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return
	}
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return
	}

	//证书写入文件（后面可以改为传到浏览器提供下载）
	if err := WirteCertToFile(inmediaCaConfig.CertPath, inmediaCaConfig.CertName, certModel.CertEncode); err != nil {
		logger.Error("Write cert file failed!", zap.Error(err))
		return
	}
}
