package services

import (
	"encoding/base64"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"go.uber.org/zap"
)

//从配置文件里面先检测是否有Intermediate是否为空
//为空就不生成中间的CA，否则拉起配置好的中间CA
func ProductIntermediateCA() error {
	n := len(AllConfig.IntermediateCaConf)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		if exsitIntermediateCA(AllConfig.IntermediateCaConf[i]) {
			continue
		}
		err := genIntermediateCA(AllConfig.IntermediateCaConf[i])
		if err != nil {
			logger.Error("Product Intermediate CA failed", zap.Error(err))
			return err
		}
	}
	return nil
}
func exsitIntermediateCA(caConfig *utils.CaConfig) bool {
	_, err := models.FindCertInfoByConditions(caConfig.CsrConf.CN, caConfig.CsrConf.O, 0, db.INTERMRDIARY_CA)
	return err == nil
}

func genIntermediateCA(caConfig *utils.CaConfig) error {
	caType, _ := getCaType()
	if caType == utils.SOLO || caType == utils.SIGN || caType == utils.TLS {
		err := GenIntermediateCASoloOrSignOrTls(caConfig)
		if err != nil {
			return err
		}
	}
	if caType == utils.DOUBLE {
		err := GenIntermediateCADouble(caConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenIntermediateCASoloOrSignOrTls(caConfig *utils.CaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	if caType == utils.TLS {
		err = GenIntermediateCASelect(caConfig, db.TLS)
		if err != nil {
			return err
		}
	} else {
		err := GenIntermediateCASelect(caConfig, db.SIGN)
		if err != nil {
			return err
		}
	}
	return nil
}
func GenIntermediateCADouble(caConfig *utils.CaConfig) error {
	//这个需要签两次
	err := GenIntermediateCASelect(caConfig, db.SIGN)
	if err != nil {
		return err
	}
	err = GenIntermediateCASelect(caConfig, db.TLS)
	if err != nil {
		return err
	}
	return nil
}
func GenIntermediateCASelect(caConfig *utils.CaConfig, certUsage db.CertUsage) error {
	//先createkeypair
	generatePrivateKey, generateKeyPair, err := genPrivateKey(caConfig)
	if err != nil {
		return err
	}
	csrRequest := createCsrReq(caConfig, generatePrivateKey)
	csrRequestConf := BuildCSRReqConf(csrRequest)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		return err
	}
	certRequestConfig, err := createCertRequestConfig(caConfig, csrByte, certUsage)
	if err != nil {
		return err
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		return err
	}
	//再创建一个certInfo
	certConditions := createCertInfoCond(caConfig, certRequestConfig.CertUsage)
	certInfo, err := CreateCertInfo(certContent, generateKeyPair, certConditions)
	if err != nil {
		return err
	}
	//这里入库
	err = models.CreateCertTransaction(certContent, certInfo, generateKeyPair)
	if err != nil {
		return err
	}
	return nil
}

func genPrivateKey(caConfig *utils.CaConfig) (privateKey crypto.PrivateKey, keyPair *db.KeyPair, err error) {
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	//这些加密的方式和哈希的方式是从配置文件中读取的
	privateKeyTypeStr = AllConfig.GetKeyType()
	hashTypeStr = AllConfig.GetHashType()
	privateKeyPwd = caConfig.CertConf.PrivateKeyPwd
	return CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
}
func createCsrReq(caConfig *utils.CaConfig, privateKey crypto.PrivateKey) *CSRRequest {
	var csrRequest CSRRequest
	csrRequest.PrivateKey = privateKey
	csrRequest.Country = caConfig.CsrConf.Country
	csrRequest.Locality = caConfig.CsrConf.Locality
	csrRequest.OrgId = caConfig.CsrConf.O
	csrRequest.Province = caConfig.CsrConf.Province
	csrRequest.UserId = caConfig.CsrConf.CN
	csrRequest.UserType = db.INTERMRDIARY_CA
	return &csrRequest
}

func createCertRequestConfig(caConfig *utils.CaConfig, csrByte []byte, certUsage db.CertUsage) (*CertRequestConfig, error) {
	certInfo, err := models.FindCertInfoByConditions("", "", certUsage, db.ROOT_CA)
	if err != nil {
		return nil, err
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil {
		return nil, err
	}
	issueKeyPair, err := models.FindKeyPairBySki(certInfo.PrivateKeyId)
	if err != nil {
		return nil, err
	}
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, err
	}
	dePrivatKey, err := base64.StdEncoding.DecodeString(issueKeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	issueprivateKey, err := KeyBytesToPrivateKey(dePrivatKey, issueKeyPair.PrivateKeyPwd, issueKeyPair.HashType)
	if err != nil {
		return nil, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         crypto.HashAlgoMap[hashTypeFromConfig()],
		IssuerPrivateKey: issueprivateKey,
		IssuerCertBytes:  reCertContent,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        certUsage,
		UserType:         db.INTERMRDIARY_CA,
		CsrBytes:         csrByte,
	}

	return certRequestConfig, nil
}

func createCertInfoCond(caConfig *utils.CaConfig, certUsage db.CertUsage) *CertConditions {
	var certConditions CertConditions
	certConditions.CertUsage = certUsage
	certConditions.UserType = db.INTERMRDIARY_CA
	certConditions.UserId = caConfig.CsrConf.CN
	certConditions.OrgId = caConfig.CsrConf.O
	return &certConditions
}
