package services

import (
	"encoding/pem"
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/wx-CRA-backend/models"
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
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]

	privKey, err := cert.CreatePrivKey(keyType, inmediaCaConfig.PrivateKeyPath, inmediaCaConfig.PrivateKeyName)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
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

	block, _ := pem.Decode(privKeyRaw)
	plain := block.Bytes
	issuerPrivKey, err := asym.PrivateKeyFromDER(plain)
	if err != nil {
		logger.Error("PrivateKeyFromPEM failed!", zap.Error(err))
		return
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return
	}
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
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
