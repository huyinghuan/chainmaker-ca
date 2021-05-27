package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/x509"
	"go.uber.org/zap"
)

//init_server里面提供了log

//在实行服务之前，需要做三件事情
//1.看能否提供服务
//2.入参是否合法
//3.查询是否已经存在证书

//最后再申请完了ByCsr的要入库证书和证书信息两项
//直接一步申请的要入库证书 证书信息 和密钥对三项
func GenerateCertByCsr(generateCertByCsrReq *models.GenerateCertByCsrReq) (string, error) {
	//utils里面写了一个否提供服务的函数WhetherOrNotProvideService，参数OrgID
	empty := ""
	//检查入参合法性
	if _, err := ParseCsr(generateCertByCsrReq.CsrBytes); err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	curUserType, ok := db.Name2UserTypeMap[generateCertByCsrReq.UserType]
	if !ok {
		err := fmt.Errorf("the User Type does not meet the requirements")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	curCertUsage, ok := db.Name2CertUsageMap[generateCertByCsrReq.CertUsage]
	if !ok {
		err := fmt.Errorf("the Cert Usage does not meet the requirements")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	if !whetherOrNotProvideService(generateCertByCsrReq.OrgID, curCertUsage) {
		err := fmt.Errorf("no service provided")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	//检查完参数
	//看看证书是否存在
	certContent, err := models.FindCertContentByConditions(generateCertByCsrReq.UserID, generateCertByCsrReq.OrgID, curCertUsage, curUserType)
	if err == nil {
		return certContent.Content, err
	}
	//有了csr流，去构建CertRequestConfig
	var certRequestConfig CertRequestConfig
	certRequestConfig.HashType = crypto.HashAlgoMap[hashTypeFromConfig()]
	certRequestConfig.CsrBytes = generateCertByCsrReq.CsrBytes
	certRequestConfig.ExpireYear = int32(expireYearFromConfig())
	certRequestConfig.CertUsage = curCertUsage
	certRequestConfig.UserType = curUserType
	//下面两项没有完成
	//去数据库里面找可以签CA的私钥和证书
	//先去找相同OrgID的中间CA，找到的话就可以了
	//若没有 就直接找rootCA签就可以了，OrgID就可以了
	//需要完成一个函数，找到可签发人的私钥和证书

	certRequestConfig.IssuerPrivateKey, certRequestConfig.IssuerCertBytes, _ = searchIssuedCa(generateCertByCsrReq.OrgID, curCertUsage)
	certContent, err = IssueCertificate(&certRequestConfig)
	if err != nil {
		return empty, err
	}
	//创建certInfo
	var certConditions CertConditions
	certConditions.UserType = curUserType
	certConditions.CertUsage = curCertUsage
	certConditions.UserId = generateCertByCsrReq.UserID
	certConditions.OrgId = generateCertByCsrReq.OrgID

	certInfo, err := CreateCertInfo(certContent, "", &certConditions)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertTwoTransaction(certContent, certInfo)
	if err != nil {
		return empty, err
	}
	return certContent.Content, nil
}

func GenCert(genCertReq *models.GenCertReq) (string, string, error) {
	empty := ""
	curUserType, ok := db.Name2UserTypeMap[genCertReq.UserType]
	if !ok {
		err := fmt.Errorf("the User Type does not meet the requirements")
		logger.Error("Generate Cert error", zap.Error(err))
		return empty, empty, err
	}
	curCertUsage, ok := db.Name2CertUsageMap[genCertReq.CertUsage]
	if !ok {
		err := fmt.Errorf("the Cert Usage does not meet the requirements")
		logger.Error("Generate Cert error", zap.Error(err))
		return empty, empty, err
	}
	if !whetherOrNotProvideService(genCertReq.OrgID, curCertUsage) {
		err := fmt.Errorf("no service provided")
		logger.Error("no service provided")
		return empty, empty, err
	}

	//检查完参数看看证书是否存在
	certContent, err := models.FindCertContentByConditions(genCertReq.UserID, genCertReq.OrgID, curCertUsage, curUserType)
	if err == nil {
		//证书存在
		keyPair, err := models.FindKeyPairByConditions(genCertReq.UserID, genCertReq.OrgID, curCertUsage, curUserType)
		if err != nil {
			return certContent.Content, empty, nil
		}
		return certContent.Content, keyPair.PrivateKey, nil
	}
	//先去生成csr流文件
	var csrRequest CSRRequest
	//先createkeypair
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	//这些加密的方式和哈希的方式是从配置文件中读取的
	privateKeyTypeStr = AllConfig.GetKeyType()
	hashTypeStr = AllConfig.GetHashType()
	privateKeyPwd = genCertReq.PrivateKeyPwd
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		logger.Error("Create Key Pair failed", zap.Error(err))
		return empty, empty, err
	}
	csrRequest.PrivateKey = privateKey
	csrRequest.Country = genCertReq.Country
	csrRequest.Locality = genCertReq.Locality
	csrRequest.OrgId = genCertReq.OrgID
	csrRequest.Province = genCertReq.Province
	csrRequest.UserId = genCertReq.UserID
	csrRequest.UserType = curUserType

	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf := BuildCSRReqConf(&csrRequest)
	//用createCSR获得csr流文件
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("Create Key Pair failed", zap.Error(err))
		return empty, empty, err
	}
	//构建请求结构体
	var certRequestConfig CertRequestConfig
	//待完成
	certRequestConfig.HashType = crypto.HashAlgoMap[hashTypeFromConfig()]
	certRequestConfig.CsrBytes = csrByte
	certRequestConfig.ExpireYear = int32(expireYearFromConfig())
	certRequestConfig.CertUsage = curCertUsage
	certRequestConfig.UserType = curUserType
	//再调用
	certRequestConfig.IssuerPrivateKey, certRequestConfig.IssuerCertBytes, _ = searchIssuedCa(genCertReq.OrgID, curCertUsage)
	certContent, err = IssueCertificate(&certRequestConfig)
	if err != nil {
		logger.Error("Create Key Pair failed", zap.Error(err))
		return empty, empty, err
	}
	var certConditions CertConditions
	certConditions.UserType = curUserType
	certConditions.CertUsage = curCertUsage
	certConditions.UserId = genCertReq.UserID
	certConditions.OrgId = genCertReq.OrgID

	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, &certConditions)
	if err != nil {
		return empty, empty, err
	}
	err = models.CreateCertTransaction(certContent, certInfo, keyPair)
	if err != nil {
		return empty, empty, err
	}
	return certContent.Content, keyPair.PrivateKey, nil
}

//查询根据需求 更改入参来查询
func QueryCert(queryCertReq *models.QueryCertReq) (string, error) {
	//入参的校验
	empty := ""
	if queryCertReq.UserID == "" {
		err := fmt.Errorf("UserID is empty")
		logger.Error("Query Cert failed ", zap.Error(err))
		return empty, err
	}
	if queryCertReq.OrgID == "" {
		err := fmt.Errorf("OrgID is empty")
		logger.Error("Query Cert failed ", zap.Error(err))
		return empty, err
	}
	curUserType, ok := db.Name2UserTypeMap[queryCertReq.UserType]
	if !ok {
		err := fmt.Errorf("the User Type does not meet the requirements")
		logger.Error("Query Cert failed", zap.Error(err))
		return empty, err
	}
	curCertUsage, ok := db.Name2CertUsageMap[queryCertReq.CertUsage]
	if !ok {
		err := fmt.Errorf("the Cert Usage does not meet the requirements")
		logger.Error("Query Cert failed", zap.Error(err))
		return empty, err
	}
	certContent, err := models.FindCertContentByConditions(queryCertReq.UserID, queryCertReq.OrgID, curCertUsage, curUserType)
	if err != nil { //找不到符合条件的证书
		logger.Error("Query Cert failed ", zap.Error(err))
		return empty, err
	}
	return certContent.Content, nil
}

//根据SN找到证书
//保留证书，生成个新的证书，certinfo，
func UpdateCert(updateCert *models.UpdateCertReq) (string, error) {
	certInfo, err := models.FindCertInfoBySn(updateCert.CertSn)
	empty := ""
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	certContent, err := models.FindCertContentBySn(updateCert.CertSn)
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuedCa(certInfo.OrgId, certInfo.CertUsage)
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	csrBytes, err := base64.StdEncoding.DecodeString(certContent.CsrContent)
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         utils.Name2HashTypeMap[AllConfig.GetHashType()],
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         csrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ExpireYear:       int32(AllConfig.GetDefaultExpireTime()),
		CertUsage:        certInfo.CertUsage,
		UserType:         certInfo.UserType,
	}
	newcertContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Error("Update Cert failed", zap.Error(err))
		return empty, err
	}
	//入库证书和更新certInfo 事务
	err = models.CreateCertAndUpdateTransaction(newcertContent, certInfo)
	if err != nil {
		logger.Error("Update Cert failed", zap.Error(err))
		return empty, err
	}
	return newcertContent.Content, nil
}

func RevokedCert(revokedCertReq *models.RevokedCertReq) ([]byte, error) {
	//先检查入参 撤销者和被撤销者是否合法
	revokedCertInfo, err := models.FindCertInfoBySn(revokedCertReq.RevokedCertSn)
	if err != nil {
		logger.Error("Revoked Cert failed", zap.Error(err))
		return nil, err
	}
	_, err = models.QueryRevokedCertByRevokedSn(revokedCertReq.RevokedCertSn)
	if err == nil { //查找到了，已经被吊销了
		err = fmt.Errorf("this cert had already been revoked")
		logger.Error("Revoked Cert failed", zap.Error(err))
		return nil, err
	}
	searchSn := revokedCertInfo.IssuerSn
	var issueCertInfo *db.CertInfo
	for {
		if searchSn == 0 {
			err = fmt.Errorf("you have no right to revoke the cert")
			logger.Error("Revoked Cert failed", zap.Error(err))
			return nil, err
		}
		if searchSn == revokedCertReq.IssueCertSn {
			break
		}
		issueCertInfo, err = models.FindCertInfoBySn(searchSn)
		if err != nil {
			logger.Error("Revoked Cert failed", zap.Error(err))
			return nil, err
		}
		searchSn = issueCertInfo.IssuerSn
	}
	revokedCert := &db.RevokedCert{
		OrgId:            revokedCertInfo.OrgId,
		RevokedCertSN:    revokedCertReq.RevokedCertSn,
		Reason:           revokedCertReq.Reason,
		RevokedStartTime: revokedCertReq.RevokedStartTime,
		RevokedEndTime:   revokedCertReq.RevokedEndTime,
		RevokedBy:        revokedCertReq.IssueCertSn,
	}
	err = models.InsertRevokedCert(revokedCert)
	if err != nil {
		logger.Error("Revoked Cert failed", zap.Error(err))
		return nil, err
	}
	//接下来生成crl
	crlListReq := &models.CrlListReq{
		IssueCertSn: revokedCertReq.IssueCertSn,
	}
	crlBytes, err := CrlList(crlListReq)
	if err != nil {
		logger.Error("Revoked Cert failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}

func CrlList(crlListReq *models.CrlListReq) ([]byte, error) {
	issueCertUse, err := GetX509Certificate(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	issueKeyPair, err := models.FindKeyPairBySki(issueCertInfo.PrivateKeyId)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	issuePrivateKeyByte, err := base64.StdEncoding.DecodeString(issueKeyPair.PrivateKey)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	issuePrivateKey, err := KeyBytesToPrivateKey(issuePrivateKeyByte, issueKeyPair.PrivateKeyPwd, issueKeyPair.HashType)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	revokedCertsList, err := models.QueryRevokedCertByIssueSn(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	var revokedCerts []pkix.RevokedCertificate
	for _, value := range revokedCertsList {
		revoked := pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(value.RevokedCertSN),
			RevocationTime: time.Unix(value.RevokedEndTime, 0),
		}
		revokedCerts = append(revokedCerts, revoked)
	}
	now := time.Now()
	next := now.Add(time.Duration(utils.DefaultTime) * time.Hour) //撤销列表过期时间（4小时候这个撤销列表就不是最新的了）
	crlBytes, err := x509.CreateCRL(rand.Reader, issueCertUse, issuePrivateKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}
