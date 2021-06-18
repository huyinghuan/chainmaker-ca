/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
)

//Generate the root CA
func CreateRootCa() error {
	rootConfig := rootCaConfFromConfig()
	if rootConfig.CsrConf == nil {
		err := LoadRootCaFromConfig()
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

//Load root CA from the path in the configuration file
func LoadRootCaFromConfig() error {
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
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}
		err = LoadSingleRootCa(signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		signCertConf, err := checkRootSignConf()
		if signCertConf == nil {
			return fmt.Errorf("load root ca from config failed: the correct path to sign the cert was not found")
		}
		err = LoadSingleRootCa(signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		tlsCertConf, err := checkRootSignConf()
		if tlsCertConf == nil {
			return fmt.Errorf("load root ca from config failed: the correct path to sign the cert was not found")
		}
		if tlsCertConf == nil {
			return fmt.Errorf("load root ca from config failed: the correct path to tls the cert was not found")
		}
		err = LoadSingleRootCa(tlsCertConf, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadRootCaFromConfig(certPath, privateKeyPath string, certUsage db.CertUsage) error {
	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("load root ca failed: %s", err.Error())
	}
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("load root ca failed: %s", err.Error())
	}
	keyPair, _, err := ConvertToKeyPair(keyBytes)
	if err != nil {
		return err
	}
	cert, certContent, err := ConvertToCertContent(certBytes)
	if err != nil {
		return err
	}

	conditions := &CertConditions{
		UserType:  db.ROOT_CA,
		CertUsage: certUsage,
		UserId:    cert.Subject.CommonName,
		OrgId:     cert.Subject.Organization[0],
	}
	if exsitRootCA(conditions.UserId, conditions.OrgId, certUsage) {
		return nil
	}
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, conditions)
	if err != nil {
		return err
	}
	err = models.CreateCertAndInfoTransaction(certContent, certInfo)
	if err != nil {
		return err
	}
	return nil
}

//Load double root CA from the path in the configuration file
func LoadDoubleRootCa() error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	err = loadRootCaFromConfig(signCertConf.CertPath, signCertConf.PrivateKeyPath, db.SIGN)
	if err != nil {
		return err
	}
	err = loadRootCaFromConfig(tlsCertConf.CertPath, tlsCertConf.PrivateKeyPath, db.TLS)
	if err != nil {
		return err
	}
	return nil
}

//Load single root CA from the path in the configuration file
func LoadSingleRootCa(certConf *utils.CertConf, certUsage db.CertUsage) error {
	return loadRootCaFromConfig(certConf.CertPath, certConf.PrivateKeyPath, certUsage)
}

//Generate root CA
func GenerateRootCa(rootCaConf *utils.CaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	switch caType {
	case utils.DOUBLE_ROOT:
		err := GenerateDoubleRootCa(rootCaConf.CsrConf)
		if err != nil {
			return err
		}
	case utils.SINGLE_ROOT:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}
		err = GenerateSingleRootCa(rootCaConf.CsrConf, signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}
		err = GenerateSingleRootCa(rootCaConf.CsrConf, signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		tlsCertConf, err := checkRootSignConf()
		err = GenerateSingleRootCa(rootCaConf.CsrConf, tlsCertConf, db.TLS)
		if err != nil {
			return err
		}
	}
	return nil
}

//Generate double root CA
func GenerateDoubleRootCa(rootCsrConf *utils.CsrConf) error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	err = genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, db.SIGN, signCertConf.PrivateKeyPath, signCertConf.CertPath)
	if err != nil {
		return err
	}
	err = genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, db.TLS, tlsCertConf.PrivateKeyPath, tlsCertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

//Generate single root CA
func GenerateSingleRootCa(rootCsrConf *utils.CsrConf, rootCertConf *utils.CertConf, certUsage db.CertUsage) error {
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	err := genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, certUsage, rootCertConf.PrivateKeyPath, rootCertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

func genRootCa(rootCsrConf *utils.CsrConf, keyTypeStr, hashTypeStr string, certUsage db.CertUsage, keyPath, certPath string) error {
	err := checkCsrConf(rootCsrConf)
	if err != nil {
		return err
	}
	certInfo, err := models.FindCertInfo(rootCsrConf.CN, rootCsrConf.O, certUsage, db.ROOT_CA)
	if err != nil {
		privateKey, keyPair, err := CreateKeyPairNoEnc(keyTypeStr, hashTypeStr)
		if err != nil {
			return err
		}
		rootCertReqConf := &RootCertRequestConfig{
			PrivateKey:         privateKey,
			Country:            rootCsrConf.Country,
			Province:           rootCsrConf.Province,
			Locality:           rootCsrConf.Locality,
			OrganizationalUnit: rootCsrConf.OU,
			Organization:       rootCsrConf.O,
			CommonName:         rootCsrConf.CN,
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
			UserType:  db.ROOT_CA,
			CertUsage: certUsage,
			UserId:    rootCsrConf.CN,
			OrgId:     rootCsrConf.O,
		}
		certInfo, err = CreateCertInfo(certContent, keyPair.Ski, certConditions)
		if err != nil {
			return err
		}
		err = models.CreateCertAndInfoTransaction(certContent, certInfo)
		if err != nil {
			return err
		}
		keyBytes := []byte(keyPair.PrivateKey)
		err = WirteFile(keyPath, keyBytes)
		if err != nil {
			return fmt.Errorf("generate root ca failed:: %s", err.Error())
		}
		certBytes := []byte(certContent.Content)
		err = WirteFile(certPath, certBytes)
		if err != nil {
			return fmt.Errorf("generate root ca failed: %s", err.Error())
		}
	}
	return nil
}

//Check if rootCA already exists
func exsitRootCA(cn, o string, certUsage db.CertUsage) bool {
	_, err := models.FindCertInfo(cn, o, certUsage, db.ROOT_CA)
	return err == nil
}
