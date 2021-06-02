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
type CertAndPrivateKey struct {
	Cert       string `json:"cert"`
	PrivateKey string `json:"privateKey"`
}

func GenerateCertByCsr(generateCertByCsrReq *GenerateCertByCsrReq) (string, error) {
	//utils里面写了一个否提供服务的函数WhetherOrNotProvideService，参数OrgID
	var empty string
	//检查入参合法性
	if _, err := ParseCsr(generateCertByCsrReq.CsrBytes); err != nil {
		logger.Error("generate cert by csr failed", zap.Error(err))
		return empty, err
	}
	//看看证书是否存在
	certContent, err := models.FindActiveCertContentByConditions(generateCertByCsrReq.UserID, generateCertByCsrReq.OrgID, generateCertByCsrReq.CertUsage, generateCertByCsrReq.UserType)
	if err == nil {
		return certContent.Content, err
	}

	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		return empty, err
	}

	//下面两项没有完成
	//去数据库里面找可以签CA的私钥和证书
	//先去找相同OrgID的中间CA，找到的话就可以了
	//若没有 就直接找rootCA签就可以了，OrgID就可以了
	//需要完成一个函数，找到可签发人的私钥和证书

	issuerPrivateKey, issuerCertBytes, err := searchIssuedCa(generateCertByCsrReq.OrgID, generateCertByCsrReq.CertUsage)
	if err != nil {
		return empty, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         generateCertByCsrReq.CsrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        generateCertByCsrReq.CertUsage,
		UserType:         generateCertByCsrReq.UserType,
	}
	certContent, err = IssueCertificate(certRequestConfig)
	if err != nil {
		return empty, err
	}
	//创建certInfo
	certConditions := &CertConditions{
		UserType:   generateCertByCsrReq.UserType,
		CertUsage:  generateCertByCsrReq.CertUsage,
		UserId:     generateCertByCsrReq.UserID,
		OrgId:      generateCertByCsrReq.OrgID,
		CertStatus: db.ACTIVE,
	}
	certInfo, err := CreateCertInfo(certContent, "", certConditions)
	if err != nil {
		logger.Error("generate cert by csr failed", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertAndInfoTransaction(certContent, certInfo)
	if err != nil {
		return empty, err
	}
	return certContent.Content, nil
}

func GenCert(genCertReq *GenCertReq) (*CertAndPrivateKey, error) {
	//检查完参数看看证书是否存在
	certContent, err := models.FindActiveCertContentByConditions(genCertReq.UserID, genCertReq.OrgID, genCertReq.CertUsage, genCertReq.UserType)
	if err == nil {
		//证书存在
		keyPair, err := models.FindActiveKeyPairByConditions(genCertReq.UserID, genCertReq.OrgID, genCertReq.CertUsage, genCertReq.UserType)
		if err != nil {
			return nil, err
		}
		return &CertAndPrivateKey{
			Cert:       certContent.Content,
			PrivateKey: keyPair.PrivateKey,
		}, nil
	}
	//先去生成csr流文件
	//要先createkeypair
	//这些加密的方式和哈希的方式是从配置文件中读取的
	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	privateKeyPwd := genCertReq.PrivateKeyPwd
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      genCertReq.OrgID,
		UserId:     genCertReq.UserID,
		UserType:   genCertReq.UserType,
		Country:    genCertReq.Country,
		Locality:   genCertReq.Locality,
		Province:   genCertReq.Province,
		PrivateKey: privateKey,
	}
	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf := BuildCSRReqConf(csrRequest)
	//用createCSR获得csr流文件
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	//构建请求结构体
	issuerPrivateKey, issuerCertBytes, err := searchIssuedCa(genCertReq.OrgID, genCertReq.CertUsage)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		return nil, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		CsrBytes:         csrByte,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        genCertReq.CertUsage,
		UserType:         genCertReq.UserType,
		IssuerPrivateKey: issuerPrivateKey,
		IssuerCertBytes:  issuerCertBytes,
	}
	certContent, err = IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	certConditions := &CertConditions{
		UserType:   genCertReq.UserType,
		CertUsage:  genCertReq.CertUsage,
		UserId:     genCertReq.UserID,
		OrgId:      genCertReq.OrgID,
		CertStatus: db.ACTIVE,
	}
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, certConditions)
	if err != nil {
		return nil, err
	}
	err = models.CreateCertTransaction(certContent, certInfo, keyPair)
	if err != nil {
		return nil, err
	}
	return &CertAndPrivateKey{
		Cert:       certContent.Content,
		PrivateKey: keyPair.PrivateKey,
	}, nil
}

func QueryCert(queryCertReq *QueryCertReq) (*models.QueryCertResp, error) {
	certInfo, err := models.FindActiveCertInfoByConditions(queryCertReq.UserID, queryCertReq.OrgID, queryCertReq.CertUsage, queryCertReq.UserType)
	if err != nil { //找不到符合条件的证书
		logger.Error("query cert failed", zap.Error(err))
		return nil, err
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil { //找不到符合条件的证书
		logger.Error("query cert failed", zap.Error(err))
		return nil, err
	}
	return &models.QueryCertResp{
		UserId:      certInfo.UserId,
		OrgId:       certInfo.OrgId,
		UserType:    db.UserType2NameMap[certInfo.UserType],
		CertUsage:   db.CertUsage2NameMap[certInfo.CertUsage],
		CertStatus:  db.CertStatus2NameMap[certInfo.CertStatus],
		CertSn:      certInfo.SerialNumber,
		CertContent: certContent.Content,
		InvalidDate: certContent.InvalidDate,
	}, nil
}

func QueryCertByStatus(queryCertByStatusReq *QueryCertByStatusReq) ([]*models.QueryCertResp, error) {
	certInfoList, err := models.FindCertInfoByConditions(queryCertByStatusReq.UserID, queryCertByStatusReq.OrgID, queryCertByStatusReq.CertUsage, queryCertByStatusReq.UserType, queryCertByStatusReq.CertStatus)
	if err != nil { //找不到符合条件的证书
		logger.Error("query cert by status failed", zap.Error(err))
		return nil, err
	}
	var res []*models.QueryCertResp
	for _, certInfo := range certInfoList {
		certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
		if err != nil { //找不到符合条件的证书
			logger.Error("query cert by status failed", zap.Error(err))
			return nil, err
		}
		res = append(res, &models.QueryCertResp{
			UserId:      certInfo.UserId,
			OrgId:       certInfo.OrgId,
			UserType:    db.UserType2NameMap[certInfo.UserType],
			CertUsage:   db.CertUsage2NameMap[certInfo.CertUsage],
			CertStatus:  db.CertStatus2NameMap[certInfo.CertStatus],
			CertSn:      certInfo.SerialNumber,
			CertContent: certContent.Content,
			InvalidDate: certContent.InvalidDate,
		})
	}
	return res, nil
}

//根据SN找到证书
//保留证书，生成个新的证书，certinfo，
func UpdateCert(updateCert *UpdateCertReq) (string, error) {
	empty := ""
	certInfo, err := models.FindCertInfoBySn(updateCert.CertSn)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	if certInfo.CertStatus == db.EXPIRED {
		err = fmt.Errorf("cert Has expired")
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	certContent, err := models.FindCertContentBySn(updateCert.CertSn)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuedCa(certInfo.OrgId, certInfo.CertUsage)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	csrBytes, err := base64.StdEncoding.DecodeString(certContent.CsrContent)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         utils.Name2HashTypeMap[allConfig.GetHashType()],
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         csrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ExpireYear:       int32(allConfig.GetDefaultExpireTime()),
		CertUsage:        certInfo.CertUsage,
		UserType:         certInfo.UserType,
	}
	newcertContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	certConditions := &CertConditions{
		UserType:   certInfo.UserType,
		CertUsage:  certInfo.CertUsage,
		UserId:     certInfo.UserId,
		OrgId:      certInfo.OrgId,
		CertStatus: db.ACTIVE,
	}
	//入库证书和新certInfo 还有更新老的certInfo
	newCertInfo, err := createCertInfo(newcertContent, certInfo.PrivateKeyId, certConditions)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertAndUpdateTransaction(newcertContent, certInfo, newCertInfo)
	if err != nil {
		logger.Error("update cert failed", zap.Error(err))
		return empty, err
	}
	return newcertContent.Content, nil
}

func RevokedCert(revokedCertReq *RevokedCertReq) ([]byte, error) {
	//先检查入参 撤销者和被撤销者是否合法
	revokedCertInfo, err := models.FindCertInfoBySn(revokedCertReq.RevokedCertSn)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	_, err = models.QueryRevokedCertByRevokedSn(revokedCertReq.RevokedCertSn)
	if err == nil { //查找到了，已经被吊销了
		err = fmt.Errorf("this cert had already been revoked")
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	searchSn := revokedCertInfo.IssuerSn
	var issueCertInfo *db.CertInfo
	for searchSn != revokedCertReq.IssueCertSn {
		if searchSn == 0 {
			err = fmt.Errorf("you have no right to revoke the cert")
			logger.Error("revoked cert failed", zap.Error(err))
			return nil, err
		}
		issueCertInfo, err = models.FindCertInfoBySn(searchSn)
		if err != nil {
			logger.Error("revoked cert failed", zap.Error(err))
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
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	//接下来生成crl
	crlListReq := &CrlListReq{
		IssueCertSn: revokedCertReq.IssueCertSn,
	}
	crlBytes, err := CrlList(crlListReq)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}
func CrlList(crlListReq *CrlListReq) ([]byte, error) {
	issueCertUse, err := GetX509Certificate(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issueKeyPair, err := models.FindKeyPairBySki(issueCertInfo.PrivateKeyId)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issuePrivateKeyByte, err := base64.StdEncoding.DecodeString(issueKeyPair.PrivateKey)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issuePrivateKey, err := KeyBytesToPrivateKey(issuePrivateKeyByte, issueKeyPair.PrivateKeyPwd, issueKeyPair.HashType)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	revokedCertsList, err := models.QueryRevokedCertByIssueSn(crlListReq.IssueCertSn)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
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
	next := now.Add(utils.DefaultCRLNextTime)
	crlBytes, err := x509.CreateCRL(rand.Reader, issueCertUse, issuePrivateKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}
func CreateCsr(createCsrReq *CreateCsrReq) ([]byte, error) {
	//先去生成csr流文件
	//要先createkeypair
	//这些加密的方式和哈希的方式是从配置文件中读取的
	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	privateKeyPwd := createCsrReq.PrivateKeyPwd
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      createCsrReq.OrgID,
		UserId:     createCsrReq.UserID,
		UserType:   createCsrReq.UserType,
		Country:    createCsrReq.Country,
		Locality:   createCsrReq.Locality,
		Province:   createCsrReq.Province,
		PrivateKey: privateKey,
	}
	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf := BuildCSRReqConf(csrRequest)
	//用createCSR获得csr流文件
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	return csrByte, nil
}

func CheckParameters(orgId, userId, userTypeStr, certUsageStr string) (userType db.UserType, certUsage db.CertUsage, err error) {
	userType, err = CheckParametersUserType(userTypeStr)
	if err != nil {
		return
	}
	certUsage, err = checkParametersCertUsage(certUsageStr)
	if err != nil {
		return
	}

	if err = checkParamsOfCertReq(orgId, userType, certUsage); err != nil {
		return
	}
	return
}

func CheckParametersEmpty(parameters ...string) error {
	for _, parameter := range parameters {
		if len(parameter) == 0 {
			err := fmt.Errorf("check parameters failed: org id or user id can't be empty")
			return err
		}
	}
	return nil
}
