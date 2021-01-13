package services

import (
	"encoding/hex"
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/crypto"
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
	//生成公私钥
	privKey, keyID, err := CreateKeyPairToDB(&inmediaCaConfig)
	if err != nil {
		return
	}
	//生成CSR 不以文件形式存在，在内存和数据库中
	csrBytes, err := createCSR(privKey, inmediaCaConfig.Country, inmediaCaConfig.Locality, inmediaCaConfig.Province, inmediaCaConfig.OrganizationalUnit,
		inmediaCaConfig.Organization, inmediaCaConfig.CommonName)
	if err != nil {
		logger.Error("Create CSR failed!", zap.Error(err))
		return
	}
	//读取签发者私钥（文件或者web端形式）
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType)
	if err != nil {
		return
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return
	}
	certModel, err := IssueCertificate(hashType, db.INTERMRDIARY_CA, issuerPrivKey, csrBytes, certBytes, inmediaCaConfig.ExpireYear, nil, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return
	}
	if err != nil {
		logger.Error("Get customer id by name failed!", zap.Error(err))
		return
	}
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = keyID
	certModel.CertUsage = db.SIGN
	//certModel.ID = Getuuid()
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return
	}

	//证书写入文件（后面可以改为传到浏览器提供下载）
	certContent, err := hex.DecodeString(certModel.CertEncode)
	if err != nil {
		logger.Error("hex decode failed!", zap.Error(err))
		return
	}
	if err := WirteCertToFile(inmediaCaConfig.CertPath, inmediaCaConfig.CertName, certContent); err != nil {
		logger.Error("Write cert file failed!", zap.Error(err))
		return
	}
}
