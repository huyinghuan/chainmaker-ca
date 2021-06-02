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
	rootConfig := getRootCaConf()
	if rootConfig.CertConf == nil {
		return fmt.Errorf("create root ca failed: root cert config can't be empty")
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
	case utils.DOUBLE_ROOT:
		err := LoadDoubleRootCa()
		if err != nil {
			return err
		}
	case utils.SINGLE_ROOT:
		err := LoadSingleRootCa(rootConfig, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		err := LoadSingleRootCa(rootConfig, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		err := LoadSingleRootCa(rootConfig, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func LoadDoubleRootCa() error {
	doubleRootPathConf := getDoubleRootPathConf()
	if doubleRootPathConf == nil {
		return fmt.Errorf("load double root ca faile: double root config cant't be empty")
	}
	signKeyBytes, err := ioutil.ReadFile(doubleRootPathConf.SignPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load double root ca faile: %s", err.Error())
	}
	tlsKeyBytes, err := ioutil.ReadFile(doubleRootPathConf.TlsPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load double root ca faile: %s", err.Error())
	}
	signCertBytes, err := ioutil.ReadFile(doubleRootPathConf.SignCertPath)
	if err != nil {
		return fmt.Errorf("load double root ca faile: %s", err.Error())
	}
	tlsCertBytes, err := ioutil.ReadFile(doubleRootPathConf.TlsCertPath)
	if err != nil {
		return fmt.Errorf("load double root ca faile: %s", err.Error())
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
		UserType:   db.ROOT_CA,
		CertUsage:  db.SIGN,
		UserId:     signCert.Subject.CommonName,
		OrgId:      signCert.Subject.Organization[0],
		CertStatus: db.ACTIVE,
	}
	signCertInfo, err := CreateCertInfo(signCertContent, signKeyPair.Ski, signConditions)
	if err != nil {
		return err
	}
	tlsConditions := &CertConditions{
		UserType:   db.ROOT_CA,
		CertUsage:  db.TLS,
		UserId:     tlsCert.Subject.CommonName,
		OrgId:      tlsCert.Subject.Organization[0],
		CertStatus: db.ACTIVE,
	}
	tlsCertInfo, err := CreateCertInfo(tlsCertContent, tlsKeyPair.Ski, tlsConditions)
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

func LoadSingleRootCa(rootConfig *utils.CaConfig, certUsage db.CertUsage) error {
	keyBytes, err := ioutil.ReadFile(rootConfig.CertConf.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load single root ca failed: %s", err.Error())
	}
	certBytes, err := ioutil.ReadFile(rootConfig.CertConf.CertPath)
	if err != nil {
		return fmt.Errorf("load single root ca failed: %s", err.Error())
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
		UserType:   db.ROOT_CA,
		CertUsage:  certUsage,
		UserId:     cert.Subject.CommonName,
		OrgId:      cert.Subject.Organization[0],
		CertStatus: db.ACTIVE,
	}
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, conditions)
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
	case utils.DOUBLE_ROOT:
		err := GenerateDoubleRootCa(rootCaConf)
		if err != nil {
			return err
		}
	case utils.SINGLE_ROOT:
		err := GenerateSingleRootCa(rootCaConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		err := GenerateSingleRootCa(rootCaConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		err := GenerateSingleRootCa(rootCaConf, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateDoubleRootCa(rootCaConf *utils.CaConfig) error {
	doubleRootPathConf := getDoubleRootPathConf()
	if doubleRootPathConf == nil {
		return fmt.Errorf("generate double root ca failed: double root config cant't be empty")
	}
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
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

func GenerateSingleRootCa(rootCaConf *utils.CaConfig, certUsage db.CertUsage) error {
	privateKeyPwd := rootCaConf.CertConf.PrivateKeyPwd
	keyTypeStr := hashTypeFromConfig()
	hashTypeStr := keyTypeFromConfig()
	err := genRootCa(rootCaConf, keyTypeStr, hashTypeStr, privateKeyPwd, certUsage, rootCaConf.CertConf.PrivateKeyPath, rootCaConf.CertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

func genRootCa(rootCaConf *utils.CaConfig, keyTypeStr, hashTypeStr, privateKeyPwd string, certUsage db.CertUsage, keyPath, certPath string) error {
	var keyPair *db.KeyPair
	var certContent *db.CertContent
	certInfo, err := models.FindActiveCertInfoByConditions(rootCaConf.CsrConf.CN, rootCaConf.CsrConf.O, certUsage, db.ROOT_CA)
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
			ExpireYear:         int32(expireYearFromConfig()),
			CertUsage:          certUsage,
			UserType:           db.ROOT_CA,
			HashType:           hashTypeStr,
		}
		certContent, err := IssueCertBySelf(rootCertReqConf)
		if err != nil {
			return err
		}
		certConditions := &CertConditions{
			UserType:   db.ROOT_CA,
			CertUsage:  certUsage,
			UserId:     rootCaConf.CsrConf.CN,
			OrgId:      rootCaConf.CsrConf.O,
			CertStatus: db.ACTIVE,
		}
		certInfo, err = CreateCertInfo(certContent, keyPair.Ski, certConditions)
		if err != nil {
			return err
		}
		err = models.CreateCertTransaction(certContent, certInfo, keyPair)
		if err != nil {
			return err
		}
		return nil
	} else {
		keyPair, err = models.FindKeyPairBySki(certInfo.PrivateKeyId)
		if err != nil {
			return err
		}
		certContent, err = models.FindCertContentBySn(certInfo.SerialNumber)
		if err != nil {
			return err
		}
		logger.Info("root cert is exist,nothing to do")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("generate root ca failed:: %s", err.Error())
	}
	err = WirteFile(keyPath, keyBytes)
	if err != nil {
		return fmt.Errorf("generate root ca failed:: %s", err.Error())
	}
	certBytes, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return fmt.Errorf("generate root ca failed:: %s", err.Error())
	}
	err = WirteFile(certPath, certBytes)
	if err != nil {
		return fmt.Errorf("generate root ca failed: %s", err.Error())
	}
	return nil
}
