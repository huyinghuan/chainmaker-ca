package services

import (
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//GenerateChainMakerCert 生成chainmaker全套证书
func GenerateChainMakerCert(cmCertApplyReq *models.ChainMakerCertApplyReq) {
	//首先每个组织是root签发的一个中间CA
	//循环签发出中间CA
	for _, org := range cmCertApplyReq.Orgs {
		//生成公私钥
		//暂时采用不加密方式（调用不加密接口）
		privateKey, keyID, err := CreateUserKeyPair(org.Username, false)
		if err != nil {
			logger.Error("Create ChainMaker org keypair failed!", zap.Error(err))
			return
		}
		//生成中间证书的CSR
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, org.OrganizationalUnit,
			org.Organization, org.CommonName)
		if err != nil {
			logger.Error("Create ChainMaker org CSR failed!", zap.Error(err))
			return
		}
		//读取配置文件里的根证书
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
		privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
		if err != nil {
			logger.Error("Read private key file failed!", zap.Error(err))
			return
		}
		//私钥解密
		issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType)
		if err != nil {
			return
		}
		//读取根证书
		certBytes, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			logger.Error("Read cert file failed!", zap.Error(err))
			return
		}

		//签发中间CA证书
		certModel, err := IssueCertificate(hashType, true, issuerPrivKey, csrBytes, certBytes, defaultExpireYear, []string{}, "")
		if err != nil {
			logger.Error("Issue Cert failed!", zap.Error(err))
			return
		}
		certModel.CustomerID, err = models.GetCustomerIDByName(org.Username)
		if err != nil {
			logger.Error("Get user id by name failed!", zap.Error(err))
			return
		}
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = db.SIGN
		certModel.PrivateKeyID = keyID
		//certModel.ID = Getuuid()
		//证书入库
		err = models.InsertCert(certModel)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return
		}
		//签发节点sign证书
		err = IssueNodeCert(&org, &privateKey, certModel.SerialNumber, db.SIGN)
		if err != nil {
			logger.Error("Issue node sign cert failed!", zap.Error(err))
			return
		}
		//签发节点TLS证书
		err = IssueNodeCert(&org, &privateKey, certModel.SerialNumber, db.TLS)
		if err != nil {
			logger.Error("Issue node tls cert failed!", zap.Error(err))
			return
		}
		//签发一个user证书
	}
}

//IssueNodeCert 签发节点证书
func IssueNodeCert(org *models.Org, privateKey *crypto.PrivateKey, certSN int64, certUsage db.CertUsage) error {
	for _, node := range org.Nodes {
		//生成公私钥
		privateKey, keyID, err := CreateUserKeyPair(org.Username, true, node.NodeName)
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
		certModel, err := IssueCertificate(hashType, false, privateKey, csrBytes, cert.Content, defaultExpireYear, node.Sans, "")
		if err != nil {
			return err
		}
		userID, err := models.GetCustomerIDByName(org.Username)
		certModel.CustomerID = userID
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = certUsage
		certModel.PrivateKeyID = keyID
		err = models.InsertCert(certModel)
		if err != nil {
			logger.Error("Insert Cert to db failed!", zap.Error(err))
			return err
		}
	}
	return nil
}
