package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	hashType := crypto.HashAlgoMap[utils.GetInputOrDefault(applyCertReq.HashType, utils.GetHashType())]
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
	// //读取签发者私钥
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, false)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	cert, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	var isCA bool
	if keyPair.UserType == db.INTERMRDIARY_CA {
		isCA = true
	}
	certModel, err := IssueCertificate(hashType, isCA, keyPair.ID, issuerPrivKey, certCSR, cert.Content, applyCertReq.ExpireYear, applyCertReq.NodeSans)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}

	return certModel.Content, nil
}

// TODO 流程&& privatekeyType && HashType
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

	// //读取签发者私钥
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	isKms := utils.GetGenerateKeyPairType()
	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), cert.HashType, isKms)
	if err != nil {
		logger.Error("update cert error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certIssuer, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
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
	certModel, err := IssueCertificate(cert.HashType, false, keyPair.ID, issuerPrivKey, certCSRBytes, certIssuer.Content, updateCertReq.ExpireYear, nodeSans)
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
	_, err := revokedCert(revokedCertReq)
	return err
}

func revokedCert(revokedCertReq *models.RevokedCertReq) (*db.RevokedCert, error) {
	var revoked db.RevokedCert
	revoked.RevokedCertSN = revokedCertReq.RevokedCertSN
	revoked.Reason = revokedCertReq.Reason
	revoked.RevokedStartTime = revokedCertReq.RevokedStartTime
	revoked.RevokedEndTime = revokedCertReq.RevokedEndTime
	err := models.UpdateCertStatusRevokedBySN(revokedCertReq.RevokedCertSN)
	if err != nil {
		logger.Error("revoked cert error", zap.Error(err))
		return &revoked, err
	}
	err = models.InsertRevokedCert(&revoked)
	if err != nil {
		logger.Error("revoked cert error", zap.Error(err))
		return &revoked, err
	}
	return &revoked, nil
}

//RevokedCert 撤销证书 返回CRL文件
func RevokedCertWithCRL(revokedCertReq *models.RevokedCertReq) ([]byte, error) {
	revoked, err := revokedCert(revokedCertReq)
	if nil != err {
		return nil, err
	}
	return createRevokedCertList(revoked)
}

func createRevokedCertList(revoked *db.RevokedCert) ([]byte, error) {
	var revokedCerts []pkix.RevokedCertificate

	var revokedCert pkix.RevokedCertificate
	revokedCert.SerialNumber = big.NewInt(revoked.RevokedCertSN)
	revokedCert.RevocationTime = time.Unix(revoked.RevokedEndTime, 0)
	revokedCerts = append(revokedCerts, revokedCert)

	now := time.Now()
	next := now.Add(time.Duration(utils.GetCRLNextTime()) * time.Hour)
	//读取签发者私钥
	currentCert, err := models.GetCertBySN(revoked.RevokedCertSN)
	if err != nil {
		logger.Error("apply cert error", zap.Error(err))
		return nil, err
	}

	keyPair, err := models.GetKeyPairByID(currentCert.PrivateKeyID)
	if err != nil {
		logger.Error("apply cert error", zap.Error(err))
		return nil, err
	}
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("get all revoked list error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	var issuerPrivKey crypto.PrivateKey
	if utils.GetIntermCAPrivateKeyPwd() != "" {
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		isKms := utils.GetGenerateKeyPairType()
		issuerPrivKey, err = decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, isKms)
		if err != nil {
			logger.Error("get all revoked list error", zap.Error(err))
			return nil, err
		}
	} else {
		block, _ := pem.Decode(issuerKeyPair.PrivateKey)
		plain := block.Bytes
		issuerPrivKey, err = asym.PrivateKeyFromDER(plain)
		if err != nil {
			logger.Error("get all revoked list error", zap.Error(err))
			return nil, err
		}
	}
	//读取签发者证书
	certBytes, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if err != nil {
		logger.Error("apply cery error", zap.Error(err))
		return nil, err
	}
	cert, err := ParseCertificate(certBytes.Content)
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

func CertInfo(certId int) (*models.CertInfo, error) {
	cert, err := models.GetCertById(certId)
	if err != nil {
		return nil, err
	}
	var certInfo models.CertInfo
	certInfo.Id = cert.ID
	certInfo.InvalidDate = cert.InvalidDate
	certInfo.OrgId = cert.Organization

	pw, err := models.GetKeyPairByID(cert.PrivateKeyID)
	if err != nil {
		return nil, err
	}
	certInfo.UserType = int(pw.UserType)
	certInfo.UserStatus = int(cert.CertStatus)
	certInfo.PrivateKeyType = PrivateKeyType2NameMap[pw.KeyType]
	certInfo.PublicKeyType = PublicKeyType2NameMap[pw.KeyType] + HashType2NameMap[cert.HashType]
	certInfo.Length = len(pw.PrivateKey)
	return &certInfo, nil
}

func CertList(getCertsReq *models.GetCertsReq) (*models.Certs, error) {
	start := getCertsReq.PageSize * (getCertsReq.Page - 1)
	certs, err := models.GetCertsByConditions(getCertsReq.OrgID, start, getCertsReq.PageSize, getCertsReq.UserStatus, getCertsReq.Id, getCertsReq.CertType, int(getCertsReq.UserType), getCertsReq.StartTime)
	if err != nil {
		return nil, err
	}
	length := 0
	if certs != nil {
		length = len(certs)
	}

	certResps := models.Certs{Certs: certs, Total: length}

	return &certResps, nil
}

func Download(certId int64, keyOrTLs string) ([]byte, error) {
	cert, err := models.GetCertBySN(certId)
	if err != nil {
		return nil, err
	}

	if keyOrTLs == "cert" {
		return cert.Content, nil
	}

	if keyOrTLs == "key" {
		key, err := models.GetKeyPairByID(cert.PrivateKeyID)
		if err != nil {
			return nil, err
		}
		return key.PrivateKey, nil
	}
	return nil, nil
}

func Freeze(certSN int64) error {
	return models.UpdateCertBySN(certSN, int(db.EFFECTIVE), int(db.FREEZE))
}

func UnFreeze(certSN int64) error {
	return models.UpdateCertBySN(certSN, int(db.FREEZE), int(db.EFFECTIVE))
}
