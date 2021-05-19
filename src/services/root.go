package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/cert"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"go.uber.org/zap"
)

//InitRootCA create root ca
func InitRootCA() {
	//read ca config
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	var user db.KeyPairUser
	user.CertUsage = db.SIGN
	user.UserType = db.ROOT_CA
	user.OrgId = utils.DefaultRootOrg

	keyTypeStr := utils.GetDefaultKeyTypeFromConf()
	hashTypeStr := utils.GetDefaultHashTypeFromConf()
	//create root key pair
	privKey, keyID, err := CreateKeyPair(keyTypeStr, hashTypeStr, &user, rootCaConfig.PrivateKeyPwd)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	//write key pair to file
	keyPair, err := models.GetKeyPairByID(keyID)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	rootPrivatePath, err := utils.GetRootPrivateKeyPath("")
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	err = WritePrivKeyFile(rootPrivatePath, keyPair.PrivateKey)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	//create cert
	hashType, err := utils.GetHashType(hashTypeStr)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	O := utils.DefaultRootOrg
	OU := "root"
	CN := OU + "." + O
	rootCertConf := &RootCertRequestConfig{
		PrivateKey:         privKey,
		Country:            rootCaConfig.Country,
		Locality:           rootCaConfig.Locality,
		Province:           rootCaConfig.Province,
		OrganizationalUnit: OU,
		Organization:       O,
		CommonName:         CN,
		HashType:           hashType,
		ExpireYear:         rootCaConfig.ExpireYear,
		Sans:               []string{""},
		Uuid:               "",
	}
	certModel, err := createCACert(rootCertConf)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = keyID
	if err := models.InsertCert(certModel); err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	certContent, err := hex.DecodeString(certModel.CertEncode)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	rootCertPath, err := utils.GetRootCertPath(hashTypeStr)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	if err := WirteCertToFile(rootCertPath, certContent); err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
}

func createCACert(rootCertConf *RootCertRequestConfig) (*db.Cert, error) {
	var certModel db.Cert
	var generateCertTemplateConfig = cert.GenerateCertTemplateConfig{
		PrivKey:            rootCertConf.PrivateKey,
		IsCA:               true,
		Country:            rootCertConf.Country,
		Locality:           rootCertConf.Locality,
		Province:           rootCertConf.Province,
		OrganizationalUnit: rootCertConf.OrganizationalUnit,
		Organization:       rootCertConf.Organization,
		CommonName:         rootCertConf.CommonName,
		ExpireYear:         rootCertConf.ExpireYear,
		Sans:               rootCertConf.Sans,
	}
	template, err := cert.GenerateCertTemplate(&generateCertTemplateConfig)
	if err != nil {
		return nil, fmt.Errorf("[Create ca cert] generate cert template failed, %s", err.Error())
	}

	template.SubjectKeyId, err = cert.ComputeSKI(rootCertConf.HashType, rootCertConf.PrivateKey.PublicKey().ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create ca cert] create CA cert compute SKI failed, %s", err.Error())
	}
	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, template,
		rootCertConf.PrivateKey.PublicKey().ToStandardKey(), rootCertConf.PrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create ca cert] create CA cert failed, %s", err.Error())
	}
	certModel.IsCa = true
	certModel.SerialNumber = template.SerialNumber.Int64()
	certModel.Signature = hex.EncodeToString(template.Signature)
	certModel.HashType = rootCertConf.HashType
	certModel.IssueDate = template.NotBefore.Unix()
	certModel.InvalidDate = template.NotAfter.Unix()
	certModel.CertEncode = hex.EncodeToString(x509certEncode)
	certModel.Country = rootCertConf.Country
	certModel.ExpireYear = rootCertConf.ExpireYear
	certModel.Locality = rootCertConf.Locality
	certModel.Province = rootCertConf.Province
	certModel.Organization = rootCertConf.Organization
	certModel.OrganizationalUnit = rootCertConf.OrganizationalUnit
	certModel.CommonName = rootCertConf.CommonName
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	return &certModel, nil
}

func LoadRootCAFromConfig() {
	//read ca config
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	rootPrivateKeyBytes, err := ioutil.ReadFile(rootCaConfig.PrivateKeyPath)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	hashType, err := utils.GetHashType(utils.GetDefaultHashTypeFromConf())
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	keyType, err := utils.GetPrivateKeyType(utils.GetDefaultKeyTypeFromConf())
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	privateKey, err := ParsePrivateKey(rootPrivateKeyBytes)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	publicKeyBytes, err := privateKey.PublicKey().Bytes()
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	keyPair := &db.KeyPair{
		PrivateKey: rootPrivateKeyBytes,
		HashType:   hashType,
		KeyType:    keyType,
		ID:         Getuuid(),
		UserType:   db.ROOT_CA,
		CertUsage:  db.SIGN,
		PublicKey:  publicKeyBytes,
	}
	err = models.InsertKeyPair(keyPair)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	rootCertBytes, err := ioutil.ReadFile(rootCaConfig.CertPath)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	rootCert, err := ParseCertificate(rootCertBytes)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
	certModel := &db.Cert{
		SerialNumber:       rootCert.SerialNumber.Int64(),
		Content:            rootCertBytes,
		Signature:          hex.EncodeToString(rootCert.Signature),
		HashType:           hashType,
		Country:            rootCert.Subject.Country[0],
		Locality:           rootCert.Subject.Locality[0],
		Province:           rootCert.Subject.Province[0],
		Organization:       rootCert.Subject.Organization[0],
		OrganizationalUnit: rootCert.Subject.OrganizationalUnit[0],
		CommonName:         rootCert.Subject.CommonName,
		IsCa:               true,
		CertStatus:         db.EFFECTIVE,
		IssueDate:          rootCert.NotAfter.Unix(),
		InvalidDate:        rootCert.NotBefore.Unix(),
		PrivateKeyID:       keyPair.ID,
	}
	err = models.InsertCert(certModel)
	if err != nil {
		logger.Error("Load root ca from config error", zap.Error(err))
		return
	}
}
