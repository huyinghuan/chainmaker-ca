package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
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
func ApplyCert(applyCertReq *models.ApplyCertReq) ([]byte, error) {
	keyPair, err := models.GetKeyPairByID(applyCertReq.PrivateKeyID)
	if err != nil {
		logger.Error("Get keypair by userid failed!", zap.Error(err))
		return nil, err
	}
	privateKeyBytes := keyPair.PrivateKey
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		logger.Error("Private from der failed!", zap.Error(err))
		return nil, err
	}
	O := keyPair.OrgID + DefaultCertOrgSuffix
	OU := keyPair.UserID
	CN := OU + "." + db.CertUsage2NameMap[keyPair.CertUsage] + "." + O
	certCSR, err := createCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
		OU, O, CN)
	if err != nil {
		logger.Error("Create csr failed!", zap.Error(err))
		return nil, err
	}
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return nil, err
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType)
	if err != nil {
		logger.Error("Decrypt Private Key failed!", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return nil, err
	}
	var isCA bool
	if keyPair.UserType == db.INTERMRDIARY_CA {
		isCA = true
	}
	certModel, err := IssueCertificate(hashType, isCA, issuerPrivKey, certCSR, certBytes, applyCertReq.ExpireYear, applyCertReq.NodeSans, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return nil, err
	}
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = keyPair.ID
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
		return nil, err
	}
	return certModel.Content, nil
}

//UpdateCert 更新证书
func UpdateCert(updateCertReq *models.UpdateCertReq) ([]byte, error) {
	cert, err := models.GetCertBySN(updateCertReq.CertSN)
	if err != nil {
		logger.Error("Get cert by id failed!", zap.Error(err))
		return nil, err
	}
	certCSRBytes := cert.CsrContent
	//读取签发者私钥
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return nil, err
	}
	//私钥解密
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType)
	if err != nil {
		logger.Error(" Decrypt private key  failed!", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return nil, err
	}
	var nodeSans []string
	err = json.Unmarshal([]byte(cert.CertSans), nodeSans)
	if err != nil {
		logger.Error("Nodesans unmarshal failed!", zap.Error(err))
		return nil, err
	}
	certModel, err := IssueCertificate(hashType, cert.IsCa, issuerPrivKey, certCSRBytes, certBytes, updateCertReq.ExpireYear, nodeSans, "")
	if err != nil {
		logger.Error("Issue Cert failed!", zap.Error(err))
		return nil, err
	}
	certModel.CertStatus = cert.CertStatus
	//证书入库
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Insert Cert to db failed!", zap.Error(err))
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
	issuerPrivKeyFilePath, certFilePath := utils.GetIntermediariesPrkCert()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		logger.Error("Read private key file failed!", zap.Error(err))
		return nil, err
	}
	//私钥解密
	var issuerPrivKey crypto.PrivateKey
	if utils.GetIntermCAPrivateKeyPwd() != "" {
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		issuerPrivKey, err = decryptPrivKey(privKeyRaw, utils.GetIntermCAPrivateKeyPwd(), hashType)
		if err != nil {
			logger.Error(" Decrypt private key  failed!", zap.Error(err))
			return nil, err
		}
	} else {
		block, _ := pem.Decode(privKeyRaw)
		plain := block.Bytes
		issuerPrivKey, err = asym.PrivateKeyFromDER(plain)
		if err != nil {
			logger.Error("PrivateKeyFromPEM failed!", zap.Error(err))
			return nil, err
		}
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		logger.Error("Read cert file failed!", zap.Error(err))
		return nil, err
	}
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		logger.Error("Parse Cert failed!", zap.Error(err))
		return nil, err
	}
	crlBytes, err := x509.CreateCRL(rand.Reader, cert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
	crlPath := "./crypto-config/CRL/test.crl"
	err = ioutil.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlBytes}), os.ModePerm)
	if err != nil {
		return nil, err
	}
	return crlBytes, nil
}
