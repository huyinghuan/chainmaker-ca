package services

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//GenerateChainMakerCert 生成chainmaker全套证书
func GenerateChainMakerCert(cmCertApplyReq *models.ChainMakerCertApplyReq) error {
	//首先每个组织是root签发的一个中间CA
	//循环签发出中间CA
	for _, org := range cmCertApplyReq.Orgs {
		//生成公私钥
		//暂时采用不加密方式（调用不加密接口）
		privateKey, keyID, err := CreateUserKeyPair(org.Username)
		if err != nil {
			logger.Error("Create ChainMaker org keypair failed!", zap.Error(err))
			return err
		}
		//生成中间证书的CSR
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, org.OrganizationalUnit,
			org.Organization, org.CommonName)
		if err != nil {
			logger.Error("Create ChainMaker org CSR failed!", zap.Error(err))
			return err
		}
		//读取配置文件里的根证书
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
		privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
		if err != nil {
			logger.Error("Read private key file failed!", zap.Error(err))
			return err
		}
		//私钥解密
		issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType)
		if err != nil {
			logger.Error("Decrypt private key  failed!", zap.Error(err))
			return err
		}
		//读取根证书
		certBytes, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			logger.Error("Read cert file failed!", zap.Error(err))
			return err
		}

		//签发中间CA证书
		certModel, err := IssueCertificate(hashType, db.INTERMRDIARY_CA, issuerPrivKey, csrBytes, certBytes, defaultExpireYear, nil, "")
		if err != nil {
			logger.Error("Issue Cert failed!", zap.Error(err))
			return err
		}
		certModel.CustomerID, err = models.GetCustomerIDByName(org.Username)
		if err != nil {
			logger.Error("Get user id by name failed!", zap.Error(err))
			return err
		}
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = db.SIGN
		certModel.PrivateKeyID = keyID
		//证书入库
		err = models.InsertCert(certModel)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return err
		}
		//签发节点sign证书
		err = IssueNodeCert(cmCertApplyReq.ConsortiumID, cmCertApplyReq.ChainID, &org, &privateKey, certModel.SerialNumber, db.SIGN)
		if err != nil {
			logger.Error("Issue node sign cert failed!", zap.Error(err))
			return err
		}
		//签发节点TLS证书
		err = IssueNodeCert(cmCertApplyReq.ConsortiumID, cmCertApplyReq.ChainID, &org, &privateKey, certModel.SerialNumber, db.TLS)
		if err != nil {
			logger.Error("Issue node tls cert failed!", zap.Error(err))
			return err
		}
		//签发一个admin sign 证书
		adminCert, err := IssueCertificate(hashType, db.CUSTOMER_ADMIN, issuerPrivKey, csrBytes, certBytes, utils.GetIssureExpirationTime(), nil, "")
		adminCert.CustomerID, err = models.GetCustomerIDByName(org.Username)
		if err != nil {
			logger.Error("Get user id by name failed!", zap.Error(err))
			return err
		}
		adminCert.CertStatus = db.EFFECTIVE
		adminCert.CertUsage = db.SIGN
		adminCert.PrivateKeyID = keyID
		adminCert.ChainID = cmCertApplyReq.ChainID
		adminCert.ConsortiumID = cmCertApplyReq.ConsortiumID
		//证书入库
		err = models.InsertCert(adminCert)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return err
		}
		//签发一个admin tls 证书
		adminCert, err = IssueCertificate(hashType, db.CUSTOMER_ADMIN, issuerPrivKey, csrBytes, certBytes, utils.GetIssureExpirationTime(), nil, "")
		adminCert.CustomerID, err = models.GetCustomerIDByName(org.Username)
		if err != nil {
			logger.Error("Get user id by name failed!", zap.Error(err))
			return err
		}
		adminCert.CertStatus = db.EFFECTIVE
		adminCert.CertUsage = db.TLS
		adminCert.PrivateKeyID = keyID
		adminCert.ChainID = cmCertApplyReq.ChainID
		adminCert.ConsortiumID = cmCertApplyReq.ConsortiumID
		//证书入库
		err = models.InsertCert(adminCert)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return err
		}
	}
	return nil
}

//IssueNodeCert 签发节点证书
func IssueNodeCert(consortiumID, chainID string, org *models.Org, privateKey *crypto.PrivateKey, certSN int64, certUsage db.CertUsage) error {
	for _, node := range org.Nodes {
		//生成公私钥
		privateKey, keyID, err := CreateUserKeyPair(org.Username)
		if err != nil {
			return err
		}
		//生成CSR
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, org.OrganizationalUnit,
			org.Organization, org.CommonName)
		if err != nil {
			return err
		}
		//拿到CA证书
		cert, err := models.GetCertBySN(certSN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		certModel, err := IssueCertificate(hashType, db.NODE, privateKey, csrBytes, cert.Content, utils.GetIssureExpirationTime(), node.Sans, "")
		if err != nil {
			return err
		}
		userID, err := models.GetCustomerIDByName(org.Username)
		if err != nil {
			return err
		}
		certModel.ChainID = chainID
		certModel.ConsortiumID = consortiumID
		certModel.CustomerID = userID
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = certUsage
		certModel.PrivateKeyID = keyID
		certModel.NodeName = node.NodeName
		err = models.InsertCert(certModel)
		if err != nil {
			return err
		}
	}
	return nil
}

//ChainMakerCertFile 获取证书压缩包
func ChainMakerCertFile(req *models.ChainMakerCertApplyReq) error {
	certBasePath := utils.GetChainMakerCertPath()
	for _, org := range req.Orgs {
		orgPath := filepath.Join(certBasePath, org.CommonName)
		err := WriteCaCertFile(orgPath, &org)
		if err != nil {
			logger.Error("Write ca cert file failed!", zap.Error(err))
			return err
		}
		err = WriteNodeCertFile(orgPath, &org, req.ChainID, req.ConsortiumID)
		if err != nil {
			logger.Error("Write node cert file failed!", zap.Error(err))
			return err
		}
		err = WriteUserCertFile(orgPath, &org, req.ChainID, req.ConsortiumID)
		if err != nil {
			logger.Error("Write user cert file failed!", zap.Error(err))
			return err
		}
	}

	return nil
}

//WriteNodeCertFile .
func WriteNodeCertFile(orgPath string, org *models.Org, chainID, consortiumID string) error {
	for _, node := range org.Nodes {
		nodePath := filepath.Join(orgPath, "node", node.NodeName)
		err := CreateDir(nodePath)
		if err != nil {
			return err
		}
		nodeSignCert, err := models.GetCertByNodeNameUsage(node.NodeName, db.SIGN, chainID, consortiumID)
		if err != nil {
			return err
		}
		nodeTLSCert, err := models.GetCertByNodeNameUsage(node.NodeName, db.TLS, chainID, consortiumID)
		if err != nil {
			return err
		}
		nodeSignKey, err := models.GetKeyPairByID(nodeSignCert.PrivateKeyID)
		if err != nil {
			return err
		}
		nodeTLSKey, err := models.GetKeyPairByID(nodeTLSCert.PrivateKeyID)
		if err != nil {
			return err
		}
		nodeSignCertPath := filepath.Join(nodePath, node.NodeName+".sign.crt")
		err = ioutil.WriteFile(nodeSignCertPath, nodeSignCert.Content, os.ModePerm)
		if err != nil {
			return err
		}
		nodeSignKeyPath := filepath.Join(nodePath, node.NodeName+".sign.key")
		err = ioutil.WriteFile(nodeSignKeyPath, nodeSignKey.PrivateKey, os.ModePerm)
		if err != nil {
			return err
		}
		nodeTLSCertPath := filepath.Join(nodePath, node.NodeName+".tls.crt")
		err = ioutil.WriteFile(nodeTLSCertPath, nodeTLSCert.Content, os.ModePerm)
		if err != nil {
			return err
		}
		nodeTLSKeyPath := filepath.Join(nodePath, node.NodeName+".tls.key")
		err = ioutil.WriteFile(nodeTLSKeyPath, nodeTLSKey.PrivateKey, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

//WriteCaCertFile .
func WriteCaCertFile(orgPath string, org *models.Org) error {
	userID, err := models.GetCustomerIDByName(org.Username)
	if err != nil {
		return err
	}
	caCert, err := models.GetCertByUserType(userID, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	caPrivate, err := models.GetKeyPairByID(caCert.PrivateKeyID)
	caPath := filepath.Join(orgPath, "ca")
	caCertPath := filepath.Join(caPath, "ca.crt")
	caKeyPath := filepath.Join(caPath, "ca.key")
	if err := CreateDir(caPath); err != nil {
		return err
	}
	err = ioutil.WriteFile(caCertPath, caCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(caKeyPath, caPrivate.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//WriteUserCertFile .
func WriteUserCertFile(orgPath string, org *models.Org, chainID, consortiumID string) error {
	userCertPath := filepath.Join(orgPath, "user", org.Username)
	err := CreateDir(userCertPath)
	if err != nil {
		return err
	}
	userID, err := models.GetCustomerIDByName(org.Username)
	if err != nil {
		return err
	}
	userSignCert, err := models.GetCertByUserTypeChain(userID, db.CUSTOMER_ADMIN, db.SIGN, chainID, consortiumID)
	if err != nil {
		return err
	}
	userSignKey, err := models.GetKeyPairByID(userSignCert.PrivateKeyID)
	if err != nil {
		return err
	}
	userTLSCert, err := models.GetCertByUserTypeChain(userID, db.CUSTOMER_ADMIN, db.TLS, chainID, consortiumID)
	if err != nil {
		return err
	}
	userTLSKey, err := models.GetKeyPairByID(userTLSCert.PrivateKeyID)
	if err != nil {
		return err
	}
	userSignCertPath := filepath.Join(userCertPath, org.Username+".sign.crt")
	err = ioutil.WriteFile(userSignCertPath, userSignCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	userSignKeyPath := filepath.Join(userCertPath, org.Username+".sign.key")
	err = ioutil.WriteFile(userSignKeyPath, userSignKey.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	userTLSCertPath := filepath.Join(userCertPath, org.Username+".tls.crt")
	err = ioutil.WriteFile(userTLSCertPath, userTLSCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	userTLSKeyPath := filepath.Join(userCertPath, org.Username+".tls.key")
	err = ioutil.WriteFile(userTLSKeyPath, userTLSKey.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}
