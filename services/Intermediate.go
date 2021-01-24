package services

import (
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//CreateIntermediateCert 签发中间机构证书
func CreateIntermediateCert() {
	inmediaCaConfig, err := utils.GetIntermediate()
	if err != nil {
		logger.Error("Get Intermediate CA config failed!", zap.Error(err))
		return
	}
	err = IssueOrgCACert(inmediaCaConfig.OrgID, inmediaCaConfig.Country, inmediaCaConfig.Locality, inmediaCaConfig.Province,
		inmediaCaConfig.PrivateKeyPwd, inmediaCaConfig.ExpireYear)
	if err != nil {
		logger.Error("Issue Intermediate CA failed!", zap.Error(err))
		return
	}
}

//IssueOrgCACert .
func IssueOrgCACert(orgID, country, locality, province, privateKeyPwd string, expireYear int32) error {
	var user db.KeyPairUser
	user.CertUsage = db.SIGN
	user.UserType = db.INTERMRDIARY_CA
	user.OrgID = orgID
	//生成公私钥
	privKey, keyID, err := CreateKeyPair(&user, "", false)
	if err != nil {
		return fmt.Errorf("Create key pair failed: %v", err.Error())
	}
	O := orgID
	OU := "ca"
	CN := "ca." + O
	//生成CSR 不以文件形式存在，在内存和数据库中
	csrBytes, err := createCSR(privKey, country, locality, province, OU, O, CN)
	if err != nil {
		return fmt.Errorf("Create CSR failed: %v", err.Error())
	}
	//读取签发者私钥（文件或者web端形式）
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
	privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
	if err != nil {
		return fmt.Errorf("Read private key file failed: %v", err.Error())
	}
	//私钥解密
	issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType, false)
	if err != nil {
		return fmt.Errorf("Decrypt private key failed: %v", err.Error())
	}
	//读取签发者证书
	certBytes, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return fmt.Errorf("Read cert file failed: %v", err.Error())
	}
	_, err = IssueCertificate(hashType, true, keyID, issuerPrivKey, csrBytes, certBytes, expireYear, nil)
	if err != nil {
		return fmt.Errorf("Issue Cert failed: %v", err.Error())
	}
	return nil

}
