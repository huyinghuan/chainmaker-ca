package services

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
)

func CreateRootCa() error {
	rootConfig := allConfig.GetRootConf()
	if rootConfig.CertConf == nil {
		return fmt.Errorf("[create root] root cert config can't be empty")
	}
	if rootConfig.CsrConf == nil {
		err := LoadRootCaFromConfig(rootConfig)
		if err != nil {
			return err
		}
		return nil
	}
	err := GenerateRootCa(rootConfig)
	if err != nil {
		return err
	}
	return nil
}

func LoadRootCaFromConfig(rootConfig *utils.CaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	switch caType {
	case utils.DOUBLE:
		err := LoadDoubleRootCa()
		if err != nil {
			return err
		}
	case utils.SOLO:
		err := LoadSoloRootCa(rootConfig, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		err := LoadSoloRootCa(rootConfig, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		err := LoadSoloRootCa(rootConfig, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func LoadDoubleRootCa() error {
	doubleRootPathConf := allConfig.GetDoubleRootPathConf()
	if doubleRootPathConf == nil {
		return fmt.Errorf("[load double] double root config cant't be empty")
	}
	signKeyBytes, err := ioutil.ReadFile(doubleRootPathConf.SignPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("[load double] read sign private key file failed: %s", err.Error())
	}
	tlsKeyBytes, err := ioutil.ReadFile(doubleRootPathConf.TlsPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("[load double] read tls private key file failed: %s", err.Error())
	}
	signCertBytes, err := ioutil.ReadFile(doubleRootPathConf.SignCertPath)
	if err != nil {
		return fmt.Errorf("[load double] read sign cert file failed: %s", err.Error())
	}
	tlsCertBytes, err := ioutil.ReadFile(doubleRootPathConf.TlsCertPath)
	if err != nil {
		return fmt.Errorf("[load double] read tls cert file failed: %s", err.Error())
	}
	signKeyPair, _, err := TransfToKeyPair(doubleRootPathConf.SignPrivateKeyPwd, signKeyBytes)
	if err != nil {
		return err
	}
	tlsKeyPair, _, err := TransfToKeyPair(doubleRootPathConf.TlsPrivateKeyPwd, tlsKeyBytes)
	if err != nil {
		return err
	}
	signCert, signCertContent, err := TransfToCertContent(signCertBytes)
	if err != nil {
		return err
	}
	tlsCert, tlsCertContent, err := TransfToCertContent(tlsCertBytes)
	if err != nil {
		return err
	}
	signConditions := &CertConditions{
		UserType:  db.ROOT_CA,
		CertUsage: db.SIGN,
		UserId:    signCert.Subject.CommonName,
		OrgId:     signCert.Subject.Organization[0],
	}
	signCertInfo, err := CreateCertInfo(signCertContent, signKeyPair, signConditions)
	if err != nil {
		return err
	}
	tlsConditions := &CertConditions{
		UserType:  db.ROOT_CA,
		CertUsage: db.TLS,
		UserId:    tlsCert.Subject.CommonName,
		OrgId:     tlsCert.Subject.Organization[0],
	}
	tlsCertInfo, err := CreateCertInfo(tlsCertContent, tlsKeyPair, tlsConditions)
	if err != nil {
		return err
	}
	err = models.CreateCertTransaction(signCertContent, signCertInfo, signKeyPair)
	if err != nil {
		return err
	}
	err = models.CreateCertTransaction(tlsCertContent, tlsCertInfo, tlsKeyPair)
	if err != nil {
		return err
	}
	return nil
}

func LoadSoloRootCa(rootConfig *utils.CaConfig, certUsage db.CertUsage) error {
	keyBytes, err := ioutil.ReadFile(rootConfig.CertConf.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("[load solo] read private key file failed: %s", err.Error())
	}
	certBytes, err := ioutil.ReadFile(rootConfig.CertConf.CertPath)
	if err != nil {
		return fmt.Errorf("[load solo] read cert file failed: %s", err.Error())
	}
	keyPair, _, err := TransfToKeyPair(rootConfig.CertConf.PrivateKeyPwd, keyBytes)
	if err != nil {
		return err
	}
	cert, certContent, err := TransfToCertContent(certBytes)
	if err != nil {
		return err
	}

	conditions := &CertConditions{
		UserType:  db.ROOT_CA,
		CertUsage: certUsage,
		UserId:    cert.Subject.CommonName,
		OrgId:     cert.Subject.Organization[0],
	}
	certInfo, err := CreateCertInfo(certContent, keyPair, conditions)
	if err != nil {
		return err
	}
	err = models.CreateCertTransaction(certContent, certInfo, keyPair)
	if err != nil {
		return err
	}
	return nil
}

func GenerateRootCa(rootCaConf *utils.CaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	switch caType {
	case utils.DOUBLE:
		err := GenerateDoubleRootCa(rootCaConf)
		if err != nil {
			return err
		}
	case utils.SOLO:
		err := GenerateSoloRootCa(rootCaConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		err := GenerateSoloRootCa(rootCaConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		err := GenerateSoloRootCa(rootCaConf, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateDoubleRootCa(rootCaConf *utils.CaConfig) error {
	doubleRootPathConf := allConfig.GetDoubleRootPathConf()
	if doubleRootPathConf == nil {
		return fmt.Errorf("[gen double] double root config cant't be empty")
	}
	keyTypeStr := allConfig.GetKeyType()
	hashTypeStr := allConfig.GetHashType()
	err := genRootCa(rootCaConf, keyTypeStr, hashTypeStr, doubleRootPathConf.SignPrivateKeyPwd, db.SIGN, doubleRootPathConf.SignPrivateKeyPath, doubleRootPathConf.SignCertPath)
	if err != nil {
		return err
	}
	err = genRootCa(rootCaConf, keyTypeStr, hashTypeStr, doubleRootPathConf.TlsPrivateKeyPwd, db.TLS, doubleRootPathConf.TlsPrivateKeyPath, doubleRootPathConf.TlsCertPath)
	if err != nil {
		return err
	}
	return nil
}

func GenerateSoloRootCa(rootCaConf *utils.CaConfig, certUsage db.CertUsage) error {
	privateKeyPwd := rootCaConf.CertConf.PrivateKeyPwd
	keyTypeStr := allConfig.GetKeyType()
	hashTypeStr := allConfig.GetHashType()
	err := genRootCa(rootCaConf, keyTypeStr, hashTypeStr, privateKeyPwd, db.SIGN, rootCaConf.CertConf.PrivateKeyPath, rootCaConf.CertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

func genRootCa(rootCaConf *utils.CaConfig, keyTypeStr, hashTypeStr, privateKeyPwd string, certUsage db.CertUsage, keyPath, certPath string) error {
	_, err := models.FindCertInfoByConditions(rootCaConf.CsrConf.CN, rootCaConf.CsrConf.O, certUsage, db.ROOT_CA)
	if err != nil {
		privateKey, keyPair, err := CreateKeyPair(keyTypeStr, hashTypeStr, privateKeyPwd)
		if err != nil {
			return err
		}
		rootCertReqConf := &RootCertRequestConfig{
			PrivateKey:         privateKey,
			Country:            rootCaConf.CsrConf.Country,
			Province:           rootCaConf.CsrConf.Province,
			Locality:           rootCaConf.CsrConf.Locality,
			OrganizationalUnit: rootCaConf.CsrConf.OU,
			Organization:       rootCaConf.CsrConf.O,
			CommonName:         rootCaConf.CsrConf.CN,
			ExpireYear:         int32(allConfig.GetDefaultExpireTime()),
			CertUsage:          certUsage,
			UserType:           db.ROOT_CA,
			HashType:           hashTypeStr,
		}
		certContent, err := IssueCertBySelf(rootCertReqConf)
		if err != nil {
			return err
		}
		certConditions := &CertConditions{
			UserType:  db.ROOT_CA,
			CertUsage: certUsage,
			UserId:    rootCaConf.CsrConf.CN,
			OrgId:     rootCaConf.CsrConf.O,
		}
		certInfo, err := CreateCertInfo(certContent, keyPair, certConditions)
		if err != nil {
			return err
		}
		err = models.CreateCertTransaction(certContent, certInfo, keyPair)
		if err != nil {
			return err
		}
		keyBytes, _ := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
		err = WirteFile(keyPath, keyBytes)
		if err != nil {
			return fmt.Errorf("[gen root] write file failed: %s", err.Error())
		}
		certBytes, _ := base64.StdEncoding.DecodeString(certContent.Content)
		err = WirteFile(certPath, certBytes)
		if err != nil {
			return fmt.Errorf("[gen root] write file failed: %s", err.Error())
		}
		return nil
	}
	logger.Info("root cert is exist,nothing to do")
	return nil
}
