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
		reCertContent, _ := base64.StdEncoding.DecodeString(certContent.Content)
		return reCertContent, err
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
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		logger.Error("Generate Cert By Csr error", zap.Error(err))
		return empty, err
	}
	return reCertContent, nil
}

func GenCert(genCertReq *models.GenCertReq) ([]byte, []byte, error) {
	var empty []byte
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
		reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
		if err != nil {
			return empty, empty, err
		}
		keyPair, err := models.FindKeyPairByConditions(genCertReq.UserID, genCertReq.OrgID, curCertUsage, curUserType)
		if err != nil {
			return empty, empty, err
		}
		rePrivateKey, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
		if err != nil {
			return empty, empty, err
		}

		return reCertContent, rePrivateKey, err
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
	rePrivateKey, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	if err != nil {
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
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		logger.Error("Generate Cert  error", zap.Error(err))
		return empty, empty, err
	}
	return reCertContent, rePrivateKey, nil
}

func QueryCert(queryCertReq *models.QueryCertReq) ([]byte, error) {
	//入参的校验
	var empty []byte
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
		err = fmt.Errorf("cert is not existed")
		logger.Error("Query Cert failed ", zap.Error(err))
		return empty, err
	}
	reCertContent, _ := base64.StdEncoding.DecodeString(certContent.Content)
	return reCertContent, err
}
