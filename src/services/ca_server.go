package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto/x509"
	"go.uber.org/zap"
)

//Generate cert by csr
func GenCertByCsr(genCertByCsrReq *GenCertByCsrReq) (string, error) {
	var empty string
	err := CheckCert(genCertByCsrReq.OrgId, genCertByCsrReq.UserId, genCertByCsrReq.UserType, genCertByCsrReq.CertUsage)
	if err != nil {
		return empty, err
	}
	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		return empty, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(genCertByCsrReq.OrgId, genCertByCsrReq.UserType, genCertByCsrReq.CertUsage)
	if err != nil {
		return empty, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         genCertByCsrReq.CsrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        genCertByCsrReq.CertUsage,
		UserType:         genCertByCsrReq.UserType,
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		return empty, err
	}
	//create certInfo
	certConditions := &CertConditions{
		UserType:  genCertByCsrReq.UserType,
		CertUsage: genCertByCsrReq.CertUsage,
		UserId:    genCertByCsrReq.UserId,
		OrgId:     genCertByCsrReq.OrgId,
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

//Generate cert
func GenCert(genCertReq *GenCertReq) (*CertAndPrivateKey, error) {
	err := CheckCert(genCertReq.OrgId, genCertReq.UserId, genCertReq.UserType, genCertReq.CertUsage)
	if err != nil {
		return nil, err
	}
	//create csr
	//first create keypair
	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	privateKeyPwd := genCertReq.PrivateKeyPwd
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      genCertReq.OrgId,
		UserId:     genCertReq.UserId,
		UserType:   genCertReq.UserType,
		Country:    genCertReq.Country,
		Locality:   genCertReq.Locality,
		Province:   genCertReq.Province,
		PrivateKey: privateKey,
	}
	csrRequestConf := BuildCSRReqConf(csrRequest)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(genCertReq.OrgId, genCertReq.UserType, genCertReq.CertUsage)
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
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	certConditions := &CertConditions{
		UserType:  genCertReq.UserType,
		CertUsage: genCertReq.CertUsage,
		UserId:    genCertReq.UserId,
		OrgId:     genCertReq.OrgId,
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

//Query certs by certstatus
func QueryCerts(req *QueryCertsReq) ([]*CertInfos, error) {
	var (
		userType  db.UserType
		certUsage db.CertUsage
		err       error
	)
	userType, err = CheckParametersUserType(req.UserType)
	if err != nil {
		userType = 0
	}
	certUsage, err = checkParametersCertUsage(req.CertUsage)
	if err != nil {
		certUsage = 0
	}
	certInfoList, err := models.FindCertInfos(req.UserId, req.OrgId, certUsage, userType)
	if err != nil {
		logger.Error("query cert by status failed", zap.Error(err))
		return nil, err
	}
	var res []*CertInfos
	for _, certInfo := range certInfoList {
		certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
		if err != nil {
			logger.Error("query cert by status failed", zap.Error(err))
			return nil, err
		}
		res = append(res, &CertInfos{
			UserId:      certInfo.UserId,
			OrgId:       certInfo.OrgId,
			UserType:    db.UserType2NameMap[certInfo.UserType],
			CertUsage:   db.CertUsage2NameMap[certInfo.CertUsage],
			CertSn:      certInfo.SerialNumber,
			CertContent: certContent.Content,
			InvalidDate: certContent.InvalidDate,
		})
	}
	return res, nil
}

//renew the cert invail time
//in fact a new certificate is issued
func RenewCert(renewCertReq *RenewCertReq) (string, error) {
	var empty string
	certInfo, err := models.FindCertInfoBySn(renewCertReq.CertSn)
	if err != nil {
		logger.Error("renew cert failed", zap.Error(err))
		return empty, err
	}
	certContent, err := models.FindCertContentBySn(renewCertReq.CertSn)
	if err != nil {
		logger.Error("renew cert failed", zap.Error(err))
		return empty, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(certInfo.OrgId, certInfo.UserType, certInfo.CertUsage)
	if err != nil {
		logger.Error("renew cert failed", zap.Error(err))
		return empty, err
	}
	csrBytes := []byte(certContent.CsrContent)
	oldCert, err := ParseCertificate([]byte(certContent.Content))
	if err != nil {
		logger.Error("renew cert failed", zap.Error(err))
		return empty, err
	}
	//renew invalid date
	oldCert.NotAfter = oldCert.NotAfter.Add(time.Duration(expireYearFromConfig()) * 365 * 24 * time.Hour).UTC()

	newCertContent, err := UpdateCert(&UpdateCertConfig{
		OldCert:         oldCert,
		OldCsrBytes:     csrBytes,
		IssuerCertBytes: issuerCertBytes,
		IssuerKey:       issuerPrivateKey,
	})
	if err != nil {
		return empty, err
	}
	err = models.UpdateCertContent(certContent, newCertContent)
	if err != nil {
		return empty, err
	}
	return newCertContent.Content, nil
}

//Revoke  certificate
func RevokeCert(revokeCertReq *RevokeCertReq) ([]byte, error) {
	_, err := models.QueryRevokedCertByRevokedSn(revokeCertReq.RevokedCertSn)
	if err == nil { //find it and is already revoked
		err = fmt.Errorf("this cert had already been revoked")
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	ok, err := searchCertChain(revokeCertReq.RevokedCertSn, revokeCertReq.IssueCertSn)
	if err != nil {
		return nil, err
	}
	if !ok {
		err := fmt.Errorf("issue cert is not in revoked cert chain")
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(revokeCertReq.IssueCertSn)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	revokedCertContent, err := models.FindCertContentBySn(revokeCertReq.RevokedCertSn)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	revokedCert := &db.RevokedCert{
		OrgId:            issueCertInfo.OrgId,
		RevokedCertSN:    revokeCertReq.RevokedCertSn,
		Reason:           revokeCertReq.Reason,
		RevokedStartTime: time.Now().Unix(),
		RevokedEndTime:   revokedCertContent.InvalidDate,
		RevokedBy:        revokeCertReq.IssueCertSn,
	}
	err = models.InsertRevokedCert(revokedCert)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	//create crl
	genCrlReq := &GenCrlReq{
		IssueCertSn: revokeCertReq.IssueCertSn,
	}
	crlBytes, err := GenCrl(genCrlReq)
	if err != nil {
		logger.Error("revoked cert failed", zap.Error(err))
		return nil, err
	}
	return crlBytes, nil
}

//Get the latest crllist
func GenCrl(genCrlReq *GenCrlReq) ([]byte, error) {
	issueCertUse, err := GetX509Certificate(genCrlReq.IssueCertSn)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(genCrlReq.IssueCertSn)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issueKeyPair, err := models.FindKeyPairBySki(issueCertInfo.PrivateKeyId)
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}
	issuePrivateKeyByte := []byte(issueKeyPair.PrivateKey)
	hashPwd, err := hex.DecodeString(issueKeyPair.PrivateKeyPwd)
	if err != nil {
		return nil, err
	}

	issuePrivateKey, err := KeyBytesToPrivateKey(issuePrivateKeyByte, string(hashPwd))
	if err != nil {
		logger.Error("crl list get failed", zap.Error(err))
		return nil, err
	}

	revokedCertsList, err := models.QueryRevokedCertByIssueSn(genCrlReq.IssueCertSn)
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

//Generate csr
func GenCsr(genCsrReq *GenCsrReq) ([]byte, error) {
	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	privateKeyPwd := genCsrReq.PrivateKeyPwd
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      genCsrReq.OrgId,
		UserId:     genCsrReq.UserId,
		UserType:   genCsrReq.UserType,
		Country:    genCsrReq.Country,
		Locality:   genCsrReq.Locality,
		Province:   genCsrReq.Province,
		PrivateKey: privateKey,
	}
	csrRequestConf := BuildCSRReqConf(csrRequest)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("generate cert failed", zap.Error(err))
		return nil, err
	}
	return csrByte, nil
}

//check orgId userId usertype certusage and determine whether to provIde certificate service
func CheckParameters(orgId, userId, userTypeStr, certUsageStr string) (userType db.UserType, certUsage db.CertUsage, err error) {
	userType, err = CheckParametersUserType(userTypeStr)
	if err != nil {
		return
	}
	certUsage, err = checkParametersCertUsage(certUsageStr)
	if err != nil {
		return
	}

	if err = checkParamsOfCertReq(orgId, userId, userType, certUsage); err != nil {
		return
	}
	return
}

//check the string parametes if empty
func CheckParametersEmpty(parameters ...string) error {
	for _, parameter := range parameters {
		if len(parameter) == 0 {
			err := fmt.Errorf("check parameters failed: required parameters cannot be empty")
			return err
		}
	}
	return nil
}

func CheckCert(orgId string, userId string, userType db.UserType, certUsage db.CertUsage) error {
	if userType == db.INTERMRDIARY_CA {
		_, err := models.FindCertInfo("", orgId, certUsage, db.INTERMRDIARY_CA)
		if err == nil {
			return fmt.Errorf("the ca cert has already existed")
		}
		return nil
	}
	_, err := models.FindCertInfo(userId, orgId, certUsage, userType)
	if err == nil {
		return fmt.Errorf("the cert has already existed")
	}
	return nil
}
