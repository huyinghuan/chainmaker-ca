package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/x509"
	"go.uber.org/zap"
)

//ApplyCert 申请证书
func ApplyCert(applyCertReq *models.ApplyCertReq) ([]byte, error) {
	keyPair, err := models.GetKeyPairByID(applyCertReq.PrivateKeyID)
	if err != nil {
		logger.Error("apply cert error", zap.Error(err))
		return nil, err
	}
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	var isKms bool
	if utils.GetGenerateKeyPairType() && (keyPair.UserType == db.USER_ADMIN || keyPair.UserType == db.USER_USER) {
		isKms = true
	}
	//私钥解密
	privateKey, err := decryptPrivKey(keyPair.PrivateKey, "", hashType, isKms)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	O := keyPair.OrgID
	OU := db.UserType2NameMap[keyPair.UserType]
	CN := keyPair.UserID + "." + O
	certCSR, err := createCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
		OU, O, CN)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediatePrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType, false)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	var isCA bool
	if keyPair.UserType == db.INTERMRDIARY_CA {
		isCA = true
	}
	certModel, err := IssueCertificate(hashType, isCA, keyPair.ID, issuerPrivKey, certCSR, certBytes, applyCertReq.ExpireYear, applyCertReq.NodeSans)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}

	return certModel.Content, nil
}

//UpdateCert 更新证书
func UpdateCert(updateCertReq *models.UpdateCertReq) ([]byte, error) {
	cert, err := models.GetCertBySN(updateCertReq.CertSN)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	keyPair, err := models.GetKeyPairByID(cert.PrivateKeyID)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	certCSRBytes := cert.CsrContent
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediatePrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	isKms := utils.GetGenerateKeyPairType()
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType, isKms)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	var nodeSans []string
	err = json.Unmarshal([]byte(cert.CertSans), &nodeSans)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	certModel, err := IssueCertificate(hashType, false, keyPair.ID, issuerPrivKey, certCSRBytes, certBytes, updateCertReq.ExpireYear, nodeSans)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	err = models.UpdateCertStatusExpiredBySN(updateCertReq.CertSN)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
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
		logger.Error("revoked cert error", zap.Error(err))
		return err
	}
	err = models.InsertRevokedCert(&revoked)
	if err != nil {
		logger.Error("revoked cert error", zap.Error(err))
		return err
	}
	return nil
}

//GetRevokedCertList 返回撤销列表
func GetRevokedCertList() ([]byte, error) {
	revokedCertList, err := models.GetAllRevokedList()
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
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
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediatePrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	var issuerPrivKey crypto.PrivateKey
	if utils.GetIntermCAPrivateKeyPwd() != "" {
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		isKms := utils.GetGenerateKeyPairType()
		issuerPrivKey, err = decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType, isKms)
		if err != nil {
			logger.Error("get all revoked list error", zap.Error(err))
			return nil, err
		}
	} else {
		block, _ := pem.Decode(privKeyRaw)
		plain := block.Bytes
		issuerPrivKey, err = asym.PrivateKeyFromDER(plain)
		if err != nil {
			logger.Error("get all revoked list error", zap.Error(err))
			return nil, err
		}
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
	}
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
	}
	crlBytes, err := x509.CreateCRL(rand.Reader, cert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
	}
	pemCrl := pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlBytes})
	return pemCrl, nil
}
