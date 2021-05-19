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


//在实行服务之前，需要做两件事情
//1.看能否提供服务
//2.入参是否合法
func GenerateCertByCsr(generateCertByCsrReq *models.GenerateCertByCsrReq)([]byte, error){
	
	//有了csr流，去构建CertRequestConfig，之后调用IssueCertificate函数就可以了
	var certRequestConfig CertRequestConfig
	//之后需要构建完结构体，在完成配置文件后，这里先完成逻辑
	certRequestConfig.HashType=
	certRequestConfig.IssuerPrivateKey=
	certRequestConfig.CsrBytes=generateCertByCsrReq.CsrBytes
	certRequestConfig.IssuerCertBytes=
	certRequestConfig.ExpireYear=
	certRequestConfig.CertUsage=generateCertByCsrReq.CertUsage
	certRequestConfig.UserType=generateCertByCsrReq.UserType
	//注意上面没有完成

	return IssueCertificate(&certRequestConfig)
}


func GenCert(genCert *models.GenCert)([]byte, error){
	//先去生成csr流文件
	var csrRequest CSRRequest
	//先createkeypair
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	//这些加密的方式和哈希的方式是从配置文件中读取的
	//需要在配置文件写好之后补上
	privateKeyTypeStr = 
	hashTypeStr = 
	privateKeyPwd = genCert.PrivateKeyPwd
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Print("Create KeyPair Error")
		return
	}
	//构造数据csrRequest的假数据
	csrRequest.PrivateKey=privateKey
	csrRequest.Country=genCert.Country
	csrRequest.Locality=genCert.Locality
	csrRequest.OrgId=genCert.OrgID
	csrRequest.Province=genCert.Province
	csrRequest.UserId=genCert.UserID
	csrRequest.UserType=genCert.UserType
	
	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf:=BuildCSRReqConf(&csrRequest)
	//用createCSR获得csr流文件
	csrByte,err:=createCSR(csrRequestConf)
	if err!=nil{
		fmt.Print("createCSR byte failed")
	}
	//构建请求结构体
	var certRequestConfig CertRequestConfig
	//待完成
	certRequestConfig.HashType=
	certRequestConfig.IssuerPrivateKey=
	certRequestConfig.CsrBytes=csrByte
	certRequestConfig.IssuerCertBytes=
	certRequestConfig.ExpireYear=
	certRequestConfig.CertUsage=genCert.CertUsage
	certRequestConfig.UserType=genCertReq.UserType
	//再调用

	return IssueCertificate(&certRequestConfig)
}




// //ApplyCert 申请证书
// func ApplyCert(applyCertReq *models.ApplyCertReq) ([]byte, error) {
// 	keyPair, err := models.GetKeyPairByID(applyCertReq.PrivateKeyID)
// 	if err != nil {
// 		logger.Error("apply cert getKeyPairByID error", zap.Error(err))
// 		return nil, err
// 	}
// 	hashType := crypto.HashAlgoMap[utils.GetInputOrDefault(applyCertReq.HashType, utils.GetHashType())]
// 	var isKms bool
// 	if utils.GetGenerateKeyPairType() && (keyPair.UserType == db.USER_ADMIN || keyPair.UserType == db.USER_USER) {
// 		isKms = true
// 	}
// 	//私钥解密
// 	privateKey, err := decryptPrivKey(keyPair.PrivateKey, "", hashType, isKms)
// 	if err != nil {
// 		logger.Error("apply cery decryptPrivKey error", zap.Error(err))
// 		return nil, err
// 	}
// 	O := keyPair.OrgId
// 	OU := db.UserType2NameMap[keyPair.UserType]
// 	CN := keyPair.UserId + "." + O
// 	certCSR, err := createCSR(privateKey, applyCertReq.Country, applyCertReq.Locality, applyCertReq.Province,
// 		OU, O, CN)
// 	if err != nil {
// 		logger.Error("apply cery createCSR error", zap.Error(err))
// 		return nil, err
// 	}
// 	// //读取签发者私钥
// 	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserId, keyPair.OrgId, int(keyPair.KeyType))
// 	if err != nil {
// 		logger.Error("apply cery  getIssuerKeyPairByConditions error", zap.Error(err))
// 		return nil, err
// 	}
// 	//私钥解密
// 	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, false)
// 	if err != nil {
// 		logger.Error("apply cery decryptPrivKey error", zap.Error(err))
// 		return nil, err
// 	}
// 	//读取签发者证书
// 	cert, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
// 	if err != nil {
// 		logger.Error("apply cery getCertByPrivateKeyID error", zap.Error(err))
// 		return nil, err
// 	}
// 	var isCA bool
// 	if keyPair.UserType == db.INTERMRDIARY_CA {
// 		isCA = true
// 	}
// 	certModel, err := IssueCertificate(hashType, isCA, keyPair.ID, issuerPrivKey, certCSR, cert.Content, applyCertReq.ExpireYear, applyCertReq.NodeSans)
// 	if err != nil {
// 		logger.Error("apply cery issueCertificate error", zap.Error(err))
// 		return nil, err
// 	}

// 	return certModel.Content, nil
// }

// // TODO 流程&& privatekeyType && HashType
// //UpdateCert 更新证书
// func UpdateCert(updateCertReq *models.UpdateCertReq) ([]byte, error) {
// 	if !models.CheckCertBySNAndOrgId(updateCertReq.CertSN, updateCertReq.OrgId) {
// 		return nil, fmt.Errorf("UpdateCert Permission denied")
// 	}
// 	cert, err := models.GetCertBySN(updateCertReq.CertSN)
// 	if err != nil {
// 		logger.Error("update cert getCertBySN error", zap.Error(err))
// 		return nil, err
// 	}
// 	keyPair, err := models.GetKeyPairByID(cert.PrivateKeyID)
// 	if err != nil {
// 		logger.Error("update cert getKeyPairByID error", zap.Error(err))
// 		return nil, err
// 	}
// 	certCSRBytes := cert.CsrContent

// 	// //读取签发者私钥
// 	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserId, keyPair.OrgId, int(keyPair.KeyType))
// 	if err != nil {
// 		logger.Error("update cert getIssuerKeyPairByConditions error", zap.Error(err))
// 		return nil, err
// 	}
// 	//私钥解密
// 	isKms := utils.GetGenerateKeyPairType()
// 	issuerPrivKey, err := decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), cert.HashType, isKms)
// 	if err != nil {
// 		logger.Error("update cert decryptPrivKey error", zap.Error(err))
// 		return nil, err
// 	}
// 	//读取签发者证书
// 	certIssuer, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
// 	if err != nil {
// 		logger.Error("update cert getCertByPrivateKeyID error", zap.Error(err))
// 		return nil, err
// 	}
// 	nodeSans := []string{cert.CertSans}
// 	certModel, err := IssueCertificate(cert.HashType, false, keyPair.ID, issuerPrivKey, certCSRBytes, certIssuer.Content, updateCertReq.ExpireYear, nodeSans)
// 	if err != nil {
// 		logger.Error("update cert issueCertificate error", zap.Error(err))
// 		return nil, err
// 	}
// 	err = models.UpdateCertStatusExpiredBySN(updateCertReq.CertSN)
// 	if err != nil {
// 		logger.Error("update cert updateCertStatusExpiredBySN error", zap.Error(err))
// 		return nil, err
// 	}
// 	return certModel.Content, nil
// }

// //RevokedCert 撤销证书
// func RevokedCert(revokedCertReq *models.RevokedCertReq) error {
// 	if !models.CheckCertBySNAndOrgId(revokedCertReq.RevokedCertSN, revokedCertReq.OrgId) {
// 		return fmt.Errorf("RevokedCert Permission denied")
// 	}
// 	_, err := revokedCert(revokedCertReq)
// 	return err
// }

// func revokedCert(revokedCertReq *models.RevokedCertReq) (*db.RevokedCert, error) {
// 	if ok, err := checkIsNotOrgCa(revokedCertReq.RevokedCertSN); ok || err != nil {
// 		return nil, fmt.Errorf("RevokedCert cert is org ca or get ca err")
// 	}

// 	var revoked db.RevokedCert
// 	revoked.RevokedCertSN = revokedCertReq.RevokedCertSN
// 	revoked.Reason = revokedCertReq.Reason
// 	revoked.RevokedStartTime = revokedCertReq.RevokedStartTime
// 	revoked.RevokedEndTime = revokedCertReq.RevokedEndTime
// 	err := models.UpdateCertStatusRevokedBySN(revokedCertReq.RevokedCertSN)
// 	if err != nil {
// 		logger.Error("revoked cert updateCertStatusRevokedBySN error", zap.Error(err))
// 		return &revoked, err
// 	}
// 	err = models.InsertRevokedCert(&revoked)
// 	if err != nil {
// 		logger.Error("revoked cert insertRevokedCert error", zap.Error(err))
// 		return &revoked, err
// 	}
// 	return &revoked, nil
// }

// //RevokedCert 撤销证书 返回CRL文件
// func RevokedCertWithCRL(revokedCertReq *models.RevokedCertReq) ([]byte, error) {
// 	if !models.CheckCertBySNAndOrgId(revokedCertReq.RevokedCertSN, revokedCertReq.OrgId) {
// 		return nil, fmt.Errorf("RevokedCertWithCRL Permission denied")
// 	}
// 	revoked, err := revokedCert(revokedCertReq)
// 	if nil != err {
// 		return nil, err
// 	}
// 	return createRevokedCertList(revoked)
// }

// func createRevokedCertList(revoked *db.RevokedCert) ([]byte, error) {
// 	var revokedCerts []pkix.RevokedCertificate

// 	var revokedCert pkix.RevokedCertificate
// 	revokedCert.SerialNumber = big.NewInt(revoked.RevokedCertSN)
// 	revokedCert.RevocationTime = time.Unix(revoked.RevokedEndTime, 0)
// 	revokedCerts = append(revokedCerts, revokedCert)

// 	now := time.Now()
// 	next := now.Add(time.Duration(utils.GetCRLNextTime()) * time.Hour)
// 	//读取签发者私钥
// 	currentCert, err := models.GetCertBySN(revoked.RevokedCertSN)
// 	if err != nil {
// 		logger.Error("revoked cert crl getCertBySN error", zap.Error(err))
// 		return nil, err
// 	}

// 	keyPair, err := models.GetKeyPairByID(currentCert.PrivateKeyID)
// 	if err != nil {
// 		logger.Error("revoked cert crl getKeyPairByID error", zap.Error(err))
// 		return nil, err
// 	}
// 	issuerKeyPair, err := models.GetIssuerKeyPairByConditions(keyPair.UserId, keyPair.OrgId, int(keyPair.KeyType))
// 	if err != nil {
// 		logger.Error("revoked cert crl getIssuerKeyPairByConditions error", zap.Error(err))
// 		return nil, err
// 	}
// 	//私钥解密
// 	var issuerPrivKey crypto.PrivateKey
// 	if utils.GetIntermCAPrivateKeyPwd() != "" {
// 		hashType := crypto.HashAlgoMap[utils.GetHashType()]
// 		isKms := utils.GetGenerateKeyPairType()
// 		issuerPrivKey, err = decryptPrivKey(issuerKeyPair.PrivateKey, utils.GetIntermCAPrivateKeyPwd(), hashType, isKms)
// 		if err != nil {
// 			logger.Error("revoked cert crl decryptPrivKey error", zap.Error(err))
// 			return nil, err
// 		}
// 	} else {
// 		block, _ := pem.Decode(issuerKeyPair.PrivateKey)
// 		plain := block.Bytes
// 		issuerPrivKey, err = asym.PrivateKeyFromDER(plain)
// 		if err != nil {
// 			logger.Error("revoked cert crl privateKeyFromDER error", zap.Error(err))
// 			return nil, err
// 		}
// 	}
// 	//读取签发者证书
// 	certBytes, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
// 	if err != nil {
// 		logger.Error("revoked cert crl getCertByPrivateKeyID error", zap.Error(err))
// 		return nil, err
// 	}
// 	cert, err := ParseCertificate(certBytes.Content)
// 	if err != nil {
// 		logger.Error("revoked cert crl parseCertificate error", zap.Error(err))
// 		return nil, err
// 	}
// 	crlBytes, err := x509.CreateCRL(rand.Reader, cert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
// 	if err != nil {
// 		logger.Error("revoked cert crl createCRL error", zap.Error(err))
// 		return nil, err
// 	}
// 	pemCrl := pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlBytes})
// 	return pemCrl, nil
// }

// func CertInfo(certId int) (*models.CertInfo, error) {
// 	cert, err := models.GetCertById(certId)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var certInfo models.CertInfo
// 	certInfo.Id = cert.ID
// 	certInfo.InvalidDate = cert.InvalidDate
// 	certInfo.OrgId = cert.Organization

// 	pw, err := models.GetKeyPairByID(cert.PrivateKeyID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	certInfo.UserType = int(pw.UserType)
// 	certInfo.UserStatus = int(cert.CertStatus)
// 	certInfo.PrivateKeyType = PrivateKeyType2NameMap[pw.KeyType]
// 	certInfo.PublicKeyType = PublicKeyType2NameMap[pw.KeyType] + "-with-" + HashType2NameMap[cert.HashType]
// 	certInfo.Length = len(pw.PrivateKey)
// 	certInfo.CertSN = cert.SerialNumber
// 	certInfo.CertType = int(pw.CertUsage)
// 	certInfo.OU = pw.UserId
// 	return &certInfo, nil
// }

// func CertList(getCertsReq *models.GetCertsReq) (*models.Certs, error) {
// 	keyType := -1
// 	userId := getCertsReq.UserId
// 	userKeyType := db.USER_ADMIN
// 	if getCertsReq.UserRole == 2 {
// 		keyType = int(db.USER_USER)
// 		userKeyType = db.USER_USER
// 	} else {
// 		userId = ""
// 	}

// 	if getCertsReq.SubUserId != "" {
// 		userId = getCertsReq.SubUserId
// 	}

// 	keyPairs, err := models.GetUserKeyPairListByConditions(int(userKeyType), getCertsReq.UserId, getCertsReq.OrgId)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// if len(keyPairs) <= 0 {
// 	// 	resp := models.Certs{Certs: []models.CertResp{}, Total: 0, CanApplyCert: true}
// 	// 	return &resp, nil
// 	// }
// 	var tmpCount tmpCount
// 	canApplyCert := checkNeedIssueCert(keyPairs, &tmpCount)

// 	start := getCertsReq.PageSize * (getCertsReq.Page - 1)
// 	certs, total, err := models.GetCertsByConditions(getCertsReq.OrgId, userId, start, getCertsReq.PageSize, getCertsReq.UserStatus, getCertsReq.Id, getCertsReq.CertType, keyType, getCertsReq.StartTime, getCertsReq.EndTime)
// 	if err != nil {
// 		return nil, err
// 	}

// 	certResps := models.Certs{Certs: certs, Total: total, CanApplyCert: canApplyCert}
// 	return &certResps, nil
// }

// func Download(downloadReq models.DownloadReq) ([]byte, error) {
// 	if !models.CheckCertBySNAndOrgId(downloadReq.CertSN, downloadReq.OrgId) {
// 		return nil, fmt.Errorf("Download Permission denied")
// 	}
// 	cert, err := models.GetCertBySN(downloadReq.CertSN)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if downloadReq.Type == "cert" {
// 		return cert.Content, nil
// 	}
// 	if ok, err := checkIsNotOrgCa(downloadReq.CertSN); ok || err != nil {
// 		return nil, fmt.Errorf("Download key is org ca or get ca err")
// 	}
// 	if downloadReq.Type == "key" {
// 		key, err := models.GetKeyPairByID(cert.PrivateKeyID)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return key.PrivateKey, nil
// 	}
// 	return nil, nil
// }

// func Freeze(freezeReq *models.FreezeReq) error {
// 	if ok, err := checkIsNotOrgCa(freezeReq.CertSN); ok || err != nil {
// 		return fmt.Errorf("RevokedCert cert is org ca or get ca err")
// 	}
// 	msg := fmt.Errorf("test:%d, %s", freezeReq.CertSN, freezeReq.OrgId)
// 	logger.Error("test:%s, %s", zap.Error(msg))
// 	if !models.CheckCertBySNAndOrgId(freezeReq.CertSN, freezeReq.OrgId) {
// 		return fmt.Errorf("Freeze Permission denied")
// 	}
// 	return models.UpdateCertBySN(freezeReq.CertSN, int(db.EFFECTIVE), int(db.FREEZE))
// }

// func UnFreeze(unfreezeReq *models.UnFreezeReq) error {
// 	if ok, err := checkIsNotOrgCa(unfreezeReq.CertSN); ok || err != nil {
// 		return fmt.Errorf("RevokedCert cert is org ca or get ca err")
// 	}
// 	if !models.CheckCertBySNAndOrgId(unfreezeReq.CertSN, unfreezeReq.OrgId) {
// 		return fmt.Errorf("UnFreeze Permission denied")
// 	}
// 	return models.UpdateCertBySN(unfreezeReq.CertSN, int(db.FREEZE), int(db.EFFECTIVE))
// }

// type tmpCount struct {
// 	SignCount        int
// 	TlsCount         int
// 	SignPrivateKeyId string
// 	TlsPrivateKeyId  string
// }

// //UserApplyCert 申请证书
// func UserApplyCert(userApplyCertReq *models.UserApplyCertReq) error {
// 	var tmpCount tmpCount
// 	userKeyType := db.USER_ADMIN
// 	if userApplyCertReq.UserRole == 2 {
// 		userKeyType = db.USER_USER
// 	}
// 	userkeyPairs, err := models.GetUserKeyPairListByConditions(int(userKeyType), userApplyCertReq.UserId, userApplyCertReq.OrgId)
// 	if nil != err {
// 		return fmt.Errorf("UserApplyCert: get user key pair error: %s", err.Error())
// 	}

// 	if !checkNeedIssueCert(userkeyPairs, &tmpCount) {
// 		return fmt.Errorf("UserApplyCert: already have certs")
// 	}

// 	keyPairs, err := models.GetIssuerKeyPairListByConditions(userApplyCertReq.UserId, userApplyCertReq.OrgId)
// 	if nil != err {
// 		return fmt.Errorf("UserApplyCert: get issuer key pair error: %s", err.Error())
// 	}
// 	issuerKeyPair := keyPairs[0]
// 	issueCert, err := models.GetCertByPrivateKeyID(issuerKeyPair.ID)
// 	if nil != err {
// 		return fmt.Errorf("UserApplyCert: get issuer cert error: %s", err.Error())
// 	}

// 	var nodeSans []string
// 	if issueCert.CertSans != "" && len(issueCert.CertSans) > 0 {
// 		if err = json.Unmarshal([]byte(issueCert.CertSans), &nodeSans); err != nil {
// 			return fmt.Errorf("UserApplyCert: json unmarshal error: %s", err.Error())
// 		}
// 	}
// 	keyType := crypto.KeyType2NameMap[issuerKeyPair.KeyType]
// 	hashType := HashType2NameMap[issueCert.HashType]
// 	userType := db.USER_USER
// 	if userApplyCertReq.UserRole == 0 {
// 		userType = db.USER_ADMIN
// 	}

// 	org := models.Org{
// 		OrgId:    userApplyCertReq.OrgId,
// 		Country:  issueCert.Country,
// 		Locality: issueCert.Locality,
// 		Province: issueCert.Province,
// 		Nodes:    nil,
// 		Users: []models.User{
// 			{UserName: userApplyCertReq.UserId,
// 				UserType: userType,
// 			},
// 		},
// 		PrivateKeyType: keyType,
// 		HashType:       hashType,
// 	}

// 	if tmpCount.SignCount+tmpCount.TlsCount == 0 {

// 		err = IssueUserCertWithStatus(&org, db.SIGN)
// 		if err != nil {
// 			return err
// 		}
// 		err = IssueUserCertWithStatus(&org, db.TLS)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	}

// 	if tmpCount.SignCount < 1 {
// 		err = IssueUserCertWithStatus(&org, db.SIGN)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	if tmpCount.TlsCount < 1 {
// 		err = IssueUserCertWithStatus(&org, db.TLS)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func checkNeedIssueCert(keyPairs []db.KeyPair, tmpCount *tmpCount) bool {
// 	if len(keyPairs) <= 1 {
// 		return true
// 	}

// 	for i := 0; i < len(keyPairs); i++ {
// 		certs, err := models.GetCertByPrivateKeyIDWithOutStatus(keyPairs[i].ID)
// 		for j := 0; j < len(certs); j++ {
// 			if err != nil {
// 				continue
// 			}
// 			if keyPairs[i].CertUsage == db.SIGN && certs[j].CertStatus == db.EFFECTIVE {
// 				tmpCount.SignCount++
// 				tmpCount.SignPrivateKeyId = keyPairs[i].ID
// 			} else if keyPairs[i].CertUsage == db.TLS && certs[j].CertStatus == db.EFFECTIVE {
// 				tmpCount.TlsCount++
// 				tmpCount.TlsPrivateKeyId = keyPairs[i].ID
// 			}
// 		}
// 	}

// 	if tmpCount.TlsCount+tmpCount.SignCount >= 2 {
// 		return false
// 	}
// 	return true
// }

// func checkIsNotOrgCa(sn int64) (bool, error) {
// 	cert, err := models.GetCertBySN(sn)
// 	if nil != err {
// 		return false, err
// 	}

// 	keyPair, err := models.GetKeyPairByID(cert.PrivateKeyID)
// 	if nil != err {
// 		return false, err
// 	}
// 	return keyPair.UserType == db.INTERMRDIARY_CA, nil
// }
