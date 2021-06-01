package services

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/crypto"
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

func GenerateCertByCsr(generateCertByCsrReq *models.GenerateCertByCsrReq) (string, error) {
	//utils里面写了一个否提供服务的函数WhetherOrNotProvideService，参数OrgID
	var empty string
	//检查入参合法性
	if _, err := ParseCsr(generateCertByCsrReq.CsrBytes); err != nil {
		logger.Error("generate cert by csr failed", zap.Error(err))
		return empty, err
	}

	curUserType, curCertUsage, err := CheckParameters(generateCertByCsrReq.OrgID, generateCertByCsrReq.UserID,
		generateCertByCsrReq.UserType, generateCertByCsrReq.CertUsage)
	if err != nil {
		logger.Error("generate cert by csr failed", zap.Error(err))
		return empty, err
	}
	//检查完参数
	//看看证书是否存在
	certContent, err := models.FindActiveCertContentByConditions(generateCertByCsrReq.UserID, generateCertByCsrReq.OrgID, curCertUsage, curUserType)
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

	issuerPrivateKey, issuerCertBytes, err := searchIssuedCa(generateCertByCsrReq.OrgID, curCertUsage)
	if err != nil {
		return empty, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         generateCertByCsrReq.CsrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        curCertUsage,
		UserType:         curUserType,
	}
	certContent, err = IssueCertificate(certRequestConfig)
	if err != nil {
		return empty, err
	}
	//创建certInfo
	certConditions := &CertConditions{
		UserType:   curUserType,
		CertUsage:  curCertUsage,
		UserId:     generateCertByCsrReq.UserID,
		OrgId:      generateCertByCsrReq.OrgID,
		CertStatus: db.ACTIVE,
	}
	certInfo, err := CreateCertInfo(certContent, "", certConditions)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertAndInfoTransaction(certContent, certInfo)
	if err != nil {
		return empty, err
	}
	return certContent.Content, nil
}

func GenCert(genCertReq *models.GenCertReq) (*CertAndPrivateKey, error) {
	curUserType, curCertUsage, err := CheckParameters(genCertReq.OrgID, genCertReq.UserID, genCertReq.UserType, genCertReq.CertUsage)
	if err != nil {
		return
	}
	//检查完参数看看证书是否存在
	certContent, err := models.FindActiveCertContentByConditions(genCertReq.UserID, genCertReq.OrgID, curCertUsage, curUserType)
	if err == nil {
		//证书存在
		keyPair, err := models.FindActiveKeyPairByConditions(genCertReq.UserID, genCertReq.OrgID, curCertUsage, curUserType)
		if err != nil {
			return
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
	privateKeyTypeStr = allConfig.GetKeyType()
	hashTypeStr = allConfig.GetHashType()
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
	certRequestConfig.IssuerPrivateKey, certRequestConfig.IssuerCertBytes, err = searchIssuedCa(genCertReq.OrgID, curCertUsage)
	if err != nil {
		logger.Error("issue certificate failed", zap.Error(err))
		return empty, empty, err
	}
	certContent, err = IssueCertificate(&certRequestConfig)
	if err != nil {
		logger.Error("issue certificate failed", zap.Error(err))
		return empty, empty, err
	}
	var certConditions CertConditions
	certConditions.UserType = curUserType
	certConditions.CertUsage = curCertUsage
	certConditions.UserId = genCertReq.UserID
	certConditions.OrgId = genCertReq.OrgID
	certConditions.CertStatus = db.ACTIVE
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

func CheckParameters(orgId, userId, userTypeStr, certUsageStr string) (userType db.UserType, certUsage db.CertUsage, err error) {
	if len(orgId) == 0 || len(userId) == 0 {
		err = fmt.Errorf("org id or user id can't be empty")
		return
	}

	userType, err = checkParametersUserType(userTypeStr)
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
