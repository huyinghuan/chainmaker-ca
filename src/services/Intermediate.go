package services

import (
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"go.uber.org/zap"
)

//CreateIntermediateCert 签发中间机构证书
func CreateIntermediateCert() {
	inmediaCaConfig, err := utils.GetIntermediate()
	if err != nil {
		logger.Error("create intermediate cert error", zap.Error(err))
		return
	}
	inmediaCaConfigOrg := models.Org{
		OrgID:          inmediaCaConfig.OrgID,
		Country:        inmediaCaConfig.Country,
		Locality:       inmediaCaConfig.Locality,
		Province:       inmediaCaConfig.Province,
		PrivateKeyType: inmediaCaConfig.PrivateKeyType,
		HashType:       inmediaCaConfig.HashType,
	}
	err = IssueOrgCACert(&inmediaCaConfigOrg, inmediaCaConfig.PrivateKeyPwd, inmediaCaConfig.ExpireYear)
	if err != nil {
		logger.Error("create intermediate cert error", zap.Error(err))
		return
	}
}

//IssueOrgCACert .
func IssueOrgCACert(org *models.Org, privateKeyPwd string, expireYear int32) error {
	country, locality, province := org.Country, org.Locality, org.Province
	var user db.KeyPairUser
	user.CertUsage = db.SIGN
	user.UserType = db.INTERMRDIARY_CA
	user.OrgID = org.OrgID
	//生成公私钥
	privKey, keyID, err := CreateKeyPair(org.PrivateKeyType, org.HashType, &user, "", false)
	if err != nil {
		return err
	}
	O := org.OrgID
	OU := "ca"
	CN := "ca." + O
	//生成CSR 不以文件形式存在，在内存和数据库中
	csrBytes, err := createCSR(privKey, country, locality, province, OU, O, CN)
	if err != nil {
		return err
	}
	//读取签发者私钥（文件或者web端形式）
	hashType := crypto.HashAlgoMap[org.HashType]
	issuerPrivKeyFilePath, certFilePath := utils.GetRootCertAndKey()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		return fmt.Errorf("[Issue org cert] read file error: %s", err.Error())
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType, false)
	if err != nil {
		return err
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return fmt.Errorf("[Issue org cert] read file error: %s", err.Error())
	}
	_, err = IssueCertificate(hashType, true, keyID, issuerPrivKey, csrBytes, certBytes, expireYear, nil)
	if err != nil {
		return err
	}
	return nil

}
