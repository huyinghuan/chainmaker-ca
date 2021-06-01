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
	certContent, err := models.FindActiveCertContentByConditions(queryCertReq.UserID, queryCertReq.OrgID, curCertUsage, curUserType)
	if err != nil { //找不到符合条件的证书
		logger.Error("Query Cert failed ", zap.Error(err))
		return empty, err
	}
	return certContent.Content, nil
}

func QueryCertByStatus(queryCertByStatusReq *models.QueryCertByStatusReq) ([]string, error) {
	if queryCertByStatusReq.UserID == "" {
		err := fmt.Errorf("UserID is empty")
		logger.Error("Query Cert failed ", zap.Error(err))
		return nil, err
	}
	if queryCertByStatusReq.OrgID == "" {
		err := fmt.Errorf("OrgID is empty")
		logger.Error("Query Cert failed ", zap.Error(err))
		return nil, err
	}
	curUserType, ok := db.Name2UserTypeMap[queryCertByStatusReq.UserType]
	if !ok {
		err := fmt.Errorf("the User Type does not meet the requirements")
		logger.Error("Query Cert failed", zap.Error(err))
		return nil, err
	}
	curCertUsage, ok := db.Name2CertUsageMap[queryCertByStatusReq.CertUsage]
	if !ok {
		err := fmt.Errorf("the Cert Usage does not meet the requirements")
		logger.Error("Query Cert failed", zap.Error(err))
		return nil, err
	}
	curCertStatus, ok := db.Name2CertStatusMap[queryCertByStatusReq.CertStatus]
	if !ok {
		err := fmt.Errorf("the Cert Status does not meet the requirements")
		logger.Error("Query Cert failed", zap.Error(err))
		return nil, err
	}
	certContentList, err := models.FindCertContentByConditions(queryCertByStatusReq.UserID, queryCertByStatusReq.OrgID, curCertUsage, curUserType, curCertStatus)
	if err != nil { //找不到符合条件的证书
		logger.Error("Query Cert By Status failed ", zap.Error(err))
		return nil, err
	}
	var res []string
	for _, value := range certContentList {
		res = append(res, value.Content)
	}
	return res, nil
}

//根据SN找到证书
//保留证书，生成个新的证书，certinfo，
func UpdateCert(updateCert *models.UpdateCertReq) (string, error) {
	empty := ""
	certInfo, err := models.FindCertInfoBySn(updateCert.CertSn)
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	if err != nil {
		logger.Error("Update Cert failed ", zap.Error(err))
		return empty, err
	}
	if certInfo.CertStatus == db.EXPIRED {
		err = fmt.Errorf("cert Has expired")
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
		logger.Error("Update Cert failed", zap.Error(err))
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
		logger.Error("Update Cert failed", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertAndUpdateTransaction(newcertContent, certInfo, newCertInfo)
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
	next := now.Add(utils.DefaultCRLNextTime)
	crlBytes, err := x509.CreateCRL(rand.Reader, issueCertUse, issuePrivateKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Error("Crl List get failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}
