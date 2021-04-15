package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
		logger.Error("apply cert getKeyPairByID error", zap.Error(err))
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
		logger.Error("apply cery decryptPrivKey error", zap.Error(err))
		return nil, err
	}
	O := keyPair.OrgID
	OU := db.UserType2NameMap[keyPair.UserType]
	CN := keyPair.UserID + "." + O
	certCSR, err := createCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
		OU, O, CN)
	if err != nil {
		logger.Error("apply cery createCSR error", zap.Error(err))
		return nil, err
	}
	// //读取签发者私钥
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("apply cery  getIssuerKeyPairByConditions error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, false)
	if err != nil {
		logger.Error("apply cery decryptPrivKey error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	cert, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if err != nil {
		logger.Error("apply cery getCertByPrivateKeyID error", zap.Error(err))
		return nil, err
	}
	var isCA bool
	if keyPair.UserType == db.INTERMRDIARY_CA {
		isCA = true
	}
	certModel, err := IssueCertificate(hashType, isCA, keyPair.ID, issuerPrivKey, certCSR, cert.Content, applyCertReq.ExpireYear, applyCertReq.NodeSans)
	if err != nil {
		logger.Error("apply cery issueCertificate error", zap.Error(err))
		return nil, err
	}

	return certModel.Content, nil
}

// TODO 流程&& privatekeyType && HashType
//UpdateCert 更新证书
func UpdateCert(updateCertReq *models.UpdateCertReq) ([]byte, error) {
	if !models.CheckCertBySNAndOrgId(updateCertReq.CertSN, updateCertReq.OrgID) {
		return nil, fmt.Errorf("UpdateCert Permission denied")
	}
	cert, err := models.GetCertBySN(updateCertReq.CertSN)
	if err != nil {
		logger.Error("update cert getCertBySN error", zap.Error(err))
		return nil, err
	}
	keyPair, err := models.GetKeyPairByID(cert.PrivateKeyID)
	if err != nil {
		logger.Error("update cert getKeyPairByID error", zap.Error(err))
		return nil, err
	}
	certCSRBytes := cert.CsrContent

	// //读取签发者私钥
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("update cert getIssuerKeyPairByConditions error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	isKms := utils.GetGenerateKeyPairType()
	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), cert.HashType, isKms)
	if err != nil {
		logger.Error("update cert decryptPrivKey error", zap.Error(err))
		return nil, err
	}
	//读取签发者证书
	certIssuer, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if err != nil {
		logger.Error("update cert getCertByPrivateKeyID error", zap.Error(err))
		return nil, err
	}
	nodeSans := []string{cert.CertSans}
	certModel, err := IssueCertificate(cert.HashType, false, keyPair.ID, issuerPrivKey, certCSRBytes, certIssuer.Content, updateCertReq.ExpireYear, nodeSans)
	if err != nil {
		logger.Error("update cert issueCertificate error", zap.Error(err))
		return nil, err
	}
	err = models.UpdateCertStatusExpiredBySN(updateCertReq.CertSN)
	if err != nil {
		logger.Error("update cert updateCertStatusExpiredBySN error", zap.Error(err))
		return nil, err
	}
	return certModel.Content, nil
}

//RevokedCert 撤销证书
func RevokedCert(revokedCertReq *models.RevokedCertReq) error {
	if !models.CheckCertBySNAndOrgId(revokedCertReq.RevokedCertSN, revokedCertReq.OrgID) {
		return fmt.Errorf("RevokedCert Permission denied")
	}
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
		logger.Error("revoked cert updateCertStatusRevokedBySN error", zap.Error(err))
		return &revoked, err
	}
	err = models.InsertRevokedCert(&revoked)
	if err != nil {
		logger.Error("revoked cert insertRevokedCert error", zap.Error(err))
		return &revoked, err
	}
	return &revoked, nil
}

//RevokedCert 撤销证书 返回CRL文件
func RevokedCertWithCRL(revokedCertReq *models.RevokedCertReq) ([]byte, error) {
	if !models.CheckCertBySNAndOrgId(revokedCertReq.RevokedCertSN, revokedCertReq.OrgID) {
		return nil, fmt.Errorf("RevokedCertWithCRL Permission denied")
	}
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
		logger.Error("revoked cert crl getCertBySN error", zap.Error(err))
		return nil, err
	}

	keyPair, err := models.GetKeyPairByID(currentCert.PrivateKeyID)
	if err != nil {
		logger.Error("revoked cert crl getKeyPairByID error", zap.Error(err))
		return nil, err
	}
	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserID, keyPair.OrgID, int(keyPair.KeyType))
	if err != nil {
		logger.Error("revoked cert crl getIssuerKeyPairByConditions error", zap.Error(err))
		return nil, err
	}
	//私钥解密
	var issuerPrivKey crypto.PrivateKey
	if utils.GetIntermCAPrivateKeyPwd() != "" {
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		isKms := utils.GetGenerateKeyPairType()
		issuerPrivKey, err = decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, isKms)
		if err != nil {
			logger.Error("revoked cert crl decryptPrivKey error", zap.Error(err))
			return nil, err
		}
	} else {
		block, _ := pem.Decode(issuerKeyPair.PrivateKey)
		plain := block.Bytes
		issuerPrivKey, err = asym.PrivateKeyFromDER(plain)
		if err != nil {
			logger.Error("revoked cert crl privateKeyFromDER error", zap.Error(err))
			return nil, err
		}
	}
	//读取签发者证书
	certBytes, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if err != nil {
		logger.Error("revoked cert crl getCertByPrivateKeyID error", zap.Error(err))
		return nil, err
	}
	cert, err := ParseCertificate(certBytes.Content)
	if err != nil {
		logger.Error("revoked cert crl parseCertificate error", zap.Error(err))
		return nil, err
	}
	crlBytes, err := x509.CreateCRL(rand.Reader, cert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Error("revoked cert crl createCRL error", zap.Error(err))
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
	certInfo.PublicKeyType = PublicKeyType2NameMap[pw.KeyType] + "-with-" + HashType2NameMap[cert.HashType]
	certInfo.Length = len(pw.PrivateKey)
	certInfo.CertSN = cert.SerialNumber
	certInfo.CertType = int(pw.CertUsage)
	certInfo.OU = pw.UserID
	return &certInfo, nil
}

func CertList(getCertsReq *models.GetCertsReq) (*models.Certs, error) {
	keyType := -1
	userId := getCertsReq.UserID
	userKeyType := db.USER_ADMIN
	if getCertsReq.UserRole == 2 {
		keyType = int(db.USER_USER)
		userKeyType = db.USER_USER
	} else {
		userId = ""
	}

	if getCertsReq.SubUserID != "" {
		userId = getCertsReq.SubUserID
	}

	keyPairs, err := models.GetUserKeyPairListByConditions(int(userKeyType), getCertsReq.UserID, getCertsReq.OrgID)
	if err != nil {
		return nil, err
	}
	// if len(keyPairs) <= 0 {
	// 	resp := models.Certs{Certs: []models.CertResp{}, Total: 0, CanApplyCert: true}
	// 	return &resp, nil
	// }
	var tmpCount tmpCount
	canApplyCert := checkNeedIssueCert(keyPairs, &tmpCount)

	start := getCertsReq.PageSize * (getCertsReq.Page - 1)
	certs, total, err := models.GetCertsByConditions(getCertsReq.OrgID, userId, start, getCertsReq.PageSize, getCertsReq.UserStatus, getCertsReq.Id, getCertsReq.CertType, keyType, getCertsReq.StartTime, getCertsReq.EndTime)
	if err != nil {
		return nil, err
	}

	certResps := models.Certs{Certs: certs, Total: total, CanApplyCert: canApplyCert}
	return &certResps, nil
}

func Download(downloadReq models.DownloadReq) ([]byte, error) {
	if !models.CheckCertBySNAndOrgId(downloadReq.CertSN, downloadReq.OrgID) {
		return nil, fmt.Errorf("Download Permission denied")
	}
	cert, err := models.GetCertBySN(downloadReq.CertSN)
	if err != nil {
		return nil, err
	}

	if downloadReq.Type == "cert" {
		return cert.Content, nil
	}

	if downloadReq.Type == "key" {
		key, err := models.GetKeyPairByID(cert.PrivateKeyID)
		if err != nil {
			return nil, err
		}
		return key.PrivateKey, nil
	}
	return nil, nil
}

func Freeze(freezeReq *models.FreezeReq) error {
	msg := fmt.Errorf("test:%d, %s", freezeReq.CertSN, freezeReq.OrgID)
	logger.Error("test:%s, %s", zap.Error(msg))
	if !models.CheckCertBySNAndOrgId(freezeReq.CertSN, freezeReq.OrgID) {
		return fmt.Errorf("Freeze Permission denied")
	}
	return models.UpdateCertBySN(freezeReq.CertSN, int(db.EFFECTIVE), int(db.FREEZE))
}

func UnFreeze(unfreezeReq *models.UnFreezeReq) error {
	if !models.CheckCertBySNAndOrgId(unfreezeReq.CertSN, unfreezeReq.OrgID) {
		return fmt.Errorf("UnFreeze Permission denied")
	}
	return models.UpdateCertBySN(unfreezeReq.CertSN, int(db.FREEZE), int(db.EFFECTIVE))
}

type tmpCount struct {
	SignCount        int
	TlsCount         int
	SignPrivateKeyId string
	TlsPrivateKeyId  string
}

//UserApplyCert 申请证书
func UserApplyCert(userApplyCertReq *models.UserApplyCertReq) error {
	var tmpCount tmpCount
	userKeyType := db.USER_ADMIN
	if userApplyCertReq.UserRole == 2 {
		userKeyType = db.USER_USER
	}
	userkeyPairs, err := models.GetUserKeyPairListByConditions(int(userKeyType), userApplyCertReq.UserID, userApplyCertReq.OrgID)
	if nil != err {
		return fmt.Errorf("UserApplyCert: get user key pair error:", err.Error())
	}

	if !checkNeedIssueCert(userkeyPairs, &tmpCount) {
		return fmt.Errorf("UserApplyCert: already have certs")
	}

	keyPairs, err := models.GetIssuerKeyPairListByConditions(userApplyCertReq.UserID, userApplyCertReq.OrgID)
	if nil != err {
		return fmt.Errorf("UserApplyCert: get issuer key pair error:", err.Error())
	}
	issuerKeyPair := keyPairs[0]
	issueCert, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
	if nil != err {
		return fmt.Errorf("UserApplyCert: get issuer cert error:", err.Error())
	}

	var nodeSans []string
	if issueCert.CertSans != "" && len(issueCert.CertSans) > 0 {
		if err = json.Unmarshal([]byte(issueCert.CertSans), &nodeSans); err != nil {
			return fmt.Errorf("UserApplyCert: json unmarshal error:", err.Error())
		}
	}
	keyType := crypto.KeyType2NameMap[issuerKeyPair.KeyType]
	hashType := HashType2NameMap[issueCert.HashType]
	userType := db.USER_USER
	if userApplyCertReq.UserRole == 0 {
		userType = db.USER_ADMIN
	}

	org := models.Org{
		OrgID:    userApplyCertReq.OrgID,
		Country:  issueCert.Country,
		Locality: issueCert.Locality,
		Province: issueCert.Province,
		Nodes:    nil,
		Users: []models.User{
			{UserName: userApplyCertReq.UserID,
				UserType: userType,
			},
		},
		PrivateKeyType: keyType,
		HashType:       hashType,
	}

	if tmpCount.SignCount+tmpCount.TlsCount == 0 {

		err = IssueUserCertWithStatus(&org, db.SIGN)
		if err != nil {
			return err
		}
		err = IssueUserCertWithStatus(&org, db.TLS)
		if err != nil {
			return err
		}
		return nil
	}

	if tmpCount.SignCount < 1 {
		err = IssueUserCertWithStatus(&org, db.SIGN)
		if err != nil {
			return err
		}
	}

	if tmpCount.TlsCount < 1 {
		err = IssueUserCertWithStatus(&org, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkNeedIssueCert(keyPairs []db.KeyPair, tmpCount *tmpCount) bool {
	if len(keyPairs) <= 1 {
		return true
	}

	for i := 0; i < len(keyPairs); i++ {
		certs, err := models.GetCertByPrivateKeyIDWithOutStatus(keyPairs[i].ID)
		for j := 0; j < len(certs); j++ {
			if err != nil {
				continue
			}
			if keyPairs[i].CertUsage == db.SIGN && certs[j].CertStatus == db.EFFECTIVE {
				tmpCount.SignCount++
				tmpCount.SignPrivateKeyId = keyPairs[i].ID
			} else if keyPairs[i].CertUsage == db.TLS && certs[j].CertStatus == db.EFFECTIVE {
				tmpCount.TlsCount++
				tmpCount.TlsPrivateKeyId = keyPairs[i].ID
			}
		}
	}

	if tmpCount.TlsCount+tmpCount.SignCount >= 2 {
		return false
	}
	return true
}
