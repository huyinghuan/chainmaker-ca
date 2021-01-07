package services

import (
	"encoding/pem"
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//ApplyCert 申请证书
func ApplyCert(applyCertReq *models.ApplyCertReq, username string) ([]byte, error) {
	userID, err := models.GetCustomerIDByName(username)
	if err != nil {
		logger.Error("Get userid failed!", zap.Error(err))
		return []byte{}, err
	}
	keyPair, err := models.GetKeyPairByUserID(userID)
	if err != nil {
		logger.Error("Get keypair by userid failed!", zap.Error(err))
		return []byte{}, err
	}
	privateKeyBytes := keyPair.PrivateKey
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		logger.Error("Private from der failed!", zap.Error(err))
		return []byte{}, err
	}
	certCSR, err := createCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
		applyCertReq.OrganizationalUnit, applyCertReq.Organization, applyCertReq.CommonName)
	if err != nil {
		logger.Error("Create csr failed!", zap.Error(err))
		return []byte{}, err
	}
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return []byte{}, err
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType)
	if err != nil {
		logger.Error("Decrypt Private Key failed!", zap.Error(err))
		return []byte{}, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return []byte{}, err
	}
	certModel, err := IssueCertificate(hashType, false, issuerPrivKey, certCSR, certBytes, applyCertReq.ExpireYear, []string{}, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return []byte{}, err
	}
	certModel.CustomerID = userID
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return []byte{}, err
	}
	return certModel.Content, nil
}

//UpdateCert 更新证书
func UpdateCert(updateCertReq *models.UpdateCertReq, username string) ([]byte, error) {
	cert, err := models.GetCertByID(updateCertReq.CertID)
	if err != nil {
		logger.Error("Get cert by id failed!", zap.Error(err))
		return []byte{}, err
	}
	userID, err := models.GetCustomerIDByName(username)
	if err != nil {
		logger.Error("Get customer id by name failed!", zap.Error(err))
		return []byte{}, err
	}
	certCSRBytes := cert.CsrContent
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return []byte{}, err
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType)
	if err != nil {
		logger.Error(" Decrypt private key  failed!", zap.Error(err))
		return []byte{}, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return []byte{}, err
	}
	certModel, err := IssueCertificate(hashType, false, issuerPrivKey, certCSRBytes, certBytes, updateCertReq.ExpireYear, []string{}, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return []byte{}, err
	}
	certModel.CustomerID = userID
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return []byte{}, err
	}
	return certModel.Content, nil
}
