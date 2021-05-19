package services

// import (
// 	"fmt"

// 	"chainmaker.org/chainmaker-ca-backend/src/models"
// 	"chainmaker.org/chainmaker-ca-backend/src/models/db"
// 	"chainmaker.org/chainmaker-ca-backend/src/utils"
// 	"chainmaker.org/chainmaker-go/common/crypto"
// 	"go.uber.org/zap"
// )

// //CreateIntermediateCert
// func CreateIntermediateCert() {
// 	inmediaCaConfig, err := utils.GetIntermediateCaConfig()
// 	if err != nil {
// 		logger.Error("create intermediate cert error", zap.Error(err))
// 		return
// 	}
// 	inmediaCaConfigOrg := &models.Org{
// 		OrgId:          inmediaCaConfig.OrgId,
// 		Country:        inmediaCaConfig.Country,
// 		Locality:       inmediaCaConfig.Locality,
// 		Province:       inmediaCaConfig.Province,
// 		ExpireYear:     inmediaCaConfig.ExpireYear,
// 		PrivateKeyPwd:  inmediaCaConfig.PrivateKeyPwd,
// 		HashType:       utils.GetDefaultHashTypeFromConf(),
// 		PrivateKeyType: utils.GetDefaultKeyTypeFromConf(),
// 	}
// 	err = IssueOrgCACert(inmediaCaConfigOrg)
// 	if err != nil {
// 		logger.Error("create intermediate cert error", zap.Error(err))
// 		return
// 	}
// }

// //IssueOrgCACert .
// func IssueOrgCACert(org *models.Org) error {
// 	err := CheckOrgInfo(org)
// 	if err != nil {
// 		return err
// 	}
// 	var user db.KeyPairUser
// 	user.CertUsage = db.SIGN
// 	user.UserType = db.INTERMRDIARY_CA
// 	user.OrgId = org.OrgId
// 	//create key pair
// 	privKey, keyID, err := CreateKeyPair(org.PrivateKeyType, org.HashType, &user, org.PrivateKeyPwd)
// 	if err != nil {
// 		return err
// 	}
// 	O := org.OrgId
// 	OU := "ca"
// 	CN := "ca." + O
// 	csrConf := &CSRRequestConfig{
// 		PrivateKey:         privKey,
// 		Province:           org.Province,
// 		Locality:           org.Locality,
// 		Country:            org.Country,
// 		OrganizationalUnit: OU,
// 		Organization:       O,
// 		CommonName:         CN,
// 	}
// 	csrBytes, err := createCSR(csrConf)
// 	if err != nil {
// 		return err
// 	}
// 	hashType, err := utils.GetHashType(org.HashType)
// 	if err != nil {
// 		return err
// 	}

// 	//find root cert and private key
// 	keyPairE, isKeyPairExist := models.KeyPairIsExist("", utils.DefaultRootOrg, db.SIGN, db.ROOT_CA)
// 	if !isKeyPairExist {
// 		return fmt.Errorf("[Issue org cert] issue org cert failed, the root certificate does not exist")
// 	}
// 	var rootPrivateKey crypto.PrivateKey
// 	if utils.GetPrivateKeyIsEncrypted() {
// 		hashType := keyPairE.HashType
// 		rootPrivateKey, err = decryptPrivKey(keyPairE.PrivateKey, keyPairE.PrivateKeyPwd, hashType)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	rootPrivateKey, err = ParsePrivateKey(keyPairE.PrivateKey)
// 	if err != nil {
// 		return err
// 	}
// 	rootCert, err := models.GetCertByPrivateKeyID(keyPairE.ID)
// 	certConf := &CertRequestConfig{
// 		HashType:         hashType,
// 		IsCa:             true,
// 		IssuerPrivateKey: rootPrivateKey,
// 		IssuerCertBytes:  rootCert.Content,
// 		CsrBytes:         csrBytes,
// 		ExpireYear:       org.ExpireYear,
// 	}
// 	_, err = IssueCertificate(certConf, keyID)
// 	if err != nil {
// 		return err
// 	}
// 	return nil

// }
