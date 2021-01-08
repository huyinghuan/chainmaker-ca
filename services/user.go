package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/x509"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
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
	certModel.CertStatus = db.EFFECTIVE
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
	certModel.CertStatus = db.EFFECTIVE
	certModel.CustomerID = userID
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return []byte{}, err
	}
	return certModel.Content, nil
}

//RevokedCert 撤销证书
func RevokedCert(revokedCertReq *models.RevokedCertReq) error {
	var revoked db.RevokedCert
	revoked.RevokedCertSN = revokedCertReq.RevokedCertSN
	revoked.Reason = revokedCertReq.Reason
	revoked.RevokedStartTime = revokedCertReq.RevokedStartTime
	revoked.RevokedEndTime = revokedCertReq.RevokedEndTime
	err := models.UpdateCertStatusRevokedBySN(revokedCertReq.RevokedCertSN)
	if err != nil {
		logger.Error("Update cert status failed!", zap.Error(err))
		return err
	}
	err = models.InsertRevokedCert(&revoked)
	if err != nil {
		logger.Error("Insert revoked cert failed!", zap.Error(err))
		return err
	}
	return nil
}

//GetRevokedCertList 返回撤销列表
func GetRevokedCertList() ([]byte, error) {
	revokedCertList, err := models.GetAllRevokedList()
	if err != nil {
		logger.Error("Get all revoked list failed!", zap.Error(err))
		return []byte{}, err
	}
	var revokedCerts []pkix.RevokedCertificate
	for _, revoked := range revokedCertList {
		var revokedCert pkix.RevokedCertificate
		revokedCert.SerialNumber = big.NewInt(revoked.RevokedCertSN)
		revokedCert.RevocationTime = time.Unix(revoked.RevokedEndTime, 0)
		revokedCerts = append(revokedCerts, revokedCert)
	}
	now := time.Now()
	next := now.Add(time.Duration(utils.GetCRLNextTime()) * time.Hour)
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
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		logger.Error("Parse Cert failed!", zap.Error(err))
		return []byte{}, err
	}
	crlBytes, err := x509.CreateCRL(rand.Reader, cert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
	return crlBytes, nil
}
