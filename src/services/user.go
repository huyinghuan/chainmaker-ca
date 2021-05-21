package services

import (
	"encoding/base64"
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
func GenerateCertByCsr(generateCertByCsrReq *models.GenerateCertByCsrReq) ([]byte, error) {
	//utils里面写了一个否提供服务的函数WhetherOrNotProvideService，参数OrgID
	var empty []byte
	if !whetherOrNotProvideService(generateCertByCsrReq.OrgID, generateCertByCsrReq.CertUsage) {
		err := fmt.Errorf("no service provided")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}

	//检查入参合法性
	if _, err := ParseCsr(generateCertByCsrReq.CsrBytes); err != nil {
		err = fmt.Errorf("the CSR file does not meet the requirements")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}

	if err := checkParametersUserType(generateCertByCsrReq.UserType); err != nil {
		return empty, err
	}

	if err := checkParametersCertUsage(generateCertByCsrReq.CertUsage); err != nil {
		return empty, err

	}
	//检查完参数
	certContent, err := models.FindCertContentByConditions(generateCertByCsrReq.UserID, generateCertByCsrReq.OrgID, generateCertByCsrReq.CertUsage, generateCertByCsrReq.UserType)
	if err == nil {
		err = fmt.Errorf("cert is existed")
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		reCertContent, _ := base64.StdEncoding.DecodeString(certContent.Content)
		return reCertContent, err
	}
	//有了csr流，去构建CertRequestConfig
	var certRequestConfig CertRequestConfig
	certRequestConfig.HashType = crypto.HashAlgoMap[hashTypeFromConfig()]
	certRequestConfig.CsrBytes = generateCertByCsrReq.CsrBytes
	certRequestConfig.ExpireYear = int32(expireYearFromConfig())
	certRequestConfig.CertUsage = generateCertByCsrReq.CertUsage
	certRequestConfig.UserType = generateCertByCsrReq.UserType
	//下面两项没有完成

	//去数据库里面找可以签CA的私钥和证书
	//先去找相同OrgID的中间CA，找到的话就可以了
	//若没有 就直接找rootCA签就可以了，OrgID就可以了
	//需要完成一个函数，找到可签发人的私钥和证书

	certRequestConfig.IssuerPrivateKey, certRequestConfig.IssuerCertBytes, _ = searchIssuedCa(generateCertByCsrReq.OrgID, generateCertByCsrReq.CertUsage)
	certContent, err = IssueCertificate(&certRequestConfig)
	if err != nil {
		return empty, err
	}

	var keyPairEmpty *db.KeyPair
	//创建certInfo
	var certConditions CertConditions
	certConditions.UserType = generateCertByCsrReq.UserType
	certConditions.CertUsage = generateCertByCsrReq.CertUsage
	certConditions.UserId = generateCertByCsrReq.UserID
	certConditions.OrgId = generateCertByCsrReq.OrgID

	certInfo, err := CreateCertInfo(certContent, keyPairEmpty, &certConditions)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	err = models.CreateCertTwoTransaction(certContent, certInfo)
	if err != nil {
		return empty, err
	}
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	return reCertContent, nil
}

func GenCert(genCertReq *models.GenCertReq) ([]byte, error) {
	var empty []byte
	if !whetherOrNotProvideService(genCertReq.OrgID, genCertReq.CertUsage) {
		err := fmt.Errorf("no service provided")
		logger.Error("no service provided")
		return empty, err
	}
	if err := checkParametersUserType(genCertReq.UserType); err != nil {
		logger.Error("user Type Wrong", zap.Error(err))
		return empty, err
	}

	if err := checkParametersCertUsage(genCertReq.CertUsage); err != nil {
		return empty, err

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
		return empty, err
	}
	csrRequest.PrivateKey = privateKey
	csrRequest.Country = genCertReq.Country
	csrRequest.Locality = genCertReq.Locality
	csrRequest.OrgId = genCertReq.OrgID
	csrRequest.Province = genCertReq.Province
	csrRequest.UserId = genCertReq.UserID
	csrRequest.UserType = genCertReq.UserType

	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf := BuildCSRReqConf(&csrRequest)
	//用createCSR获得csr流文件
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Error("Create Key Pair failed", zap.Error(err))
		return empty, err
	}
	//构建请求结构体
	var certRequestConfig CertRequestConfig
	//待完成
	certRequestConfig.HashType = crypto.HashAlgoMap[hashTypeFromConfig()]
	certRequestConfig.CsrBytes = csrByte
	certRequestConfig.ExpireYear = int32(expireYearFromConfig())
	certRequestConfig.CertUsage = genCertReq.CertUsage
	certRequestConfig.UserType = genCertReq.UserType
	//再调用
	certRequestConfig.IssuerPrivateKey, certRequestConfig.IssuerCertBytes, _ = searchIssuedCa(genCertReq.OrgID, genCertReq.CertUsage)
	certContent, err := IssueCertificate(&certRequestConfig)
	if err != nil {
		return empty, err
	}
	var certConditions CertConditions
	certConditions.UserType = genCertReq.UserType
	certConditions.CertUsage = genCertReq.CertUsage
	certConditions.UserId = genCertReq.UserID
	certConditions.OrgId = genCertReq.OrgID

	certInfo, err := CreateCertInfo(certContent, keyPair, &certConditions)
	if err != nil {
		return empty, err
	}
	err = models.CreateCertTransaction(certContent, certInfo, keyPair)
	if err != nil {
		return empty, err
	}
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	return reCertContent, nil
}
