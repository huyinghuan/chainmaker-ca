/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/conf"
	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/crypto"
	"go.uber.org/zap"
)

//CreateIntermediateCA Create intermediate CA in the configuration file
func CreateIntermediateCA() error {
	if checkIntermediateCaConf() == nil {
		logger.Info("there is not find intermediate ca config")
		return nil
	}
	imCaConfs := imCaConfFromConfig()
	for i := 0; i < len(imCaConfs); i++ {
		if imCaConfs[i] == nil {
			return nil
		}
		err := checkCsrConf(imCaConfs[i].CsrConf)
		if err != nil {
			logger.Error("create intermediate ca failed", zap.Error(err))
			continue
		}
		logger.Info("create intermediate ca", zap.Any("csr config", imCaConfs[i].CsrConf))
		if exsitIntermediateCA(imCaConfs[i].CsrConf) {
			logger.Info("the intermediate ca info is already exist")
			continue
		}
		err = createIntermediateCA(imCaConfs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

//Check if intermediate CA already exists
func exsitIntermediateCA(csrConf *conf.CsrConf) bool {
	_, err := models.FindCertInfo(csrConf.CN, csrConf.O, 0, db.INTERMRDIARY_CA)
	return err == nil
}

func createIntermediateCA(caConfig *conf.ImCaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	logger.Info("create intermediate ca", zap.String("ca type", conf.CaType2NameMap[caType]))
	if caType == conf.SINGLE_ROOT || caType == conf.SIGN || caType == conf.TLS {
		err := GenSingleIntermediateCA(caConfig, caType)
		if err != nil {
			return err
		}
	}
	if caType == conf.DOUBLE_ROOT {
		err := GenDoubleIntermediateCA(caConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

//Generate intermediate CA if catype is single_root
func GenSingleIntermediateCA(caConfig *conf.ImCaConfig, caType conf.CaType) error {
	if caType == conf.TLS {
		tlsCertConf, err := checkRootTlsConf()
		if err != nil {
			return err
		}
		logger.Info("generate single intermediate CA", zap.Any("root tls cert conf", tlsCertConf))
		err = genIntermediateCA(caConfig, db.TLS, tlsCertConf.PrivateKeyPath)
		if err != nil {
			return err
		}
	}
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	logger.Info("generate single intermediate CA", zap.Any("root sign cert conf", signCertConf))
	err = genIntermediateCA(caConfig, db.SIGN, signCertConf.PrivateKeyPath)
	if err != nil {
		return err
	}
	return nil
}

//Generate intermediate CA if catype is double_root
func GenDoubleIntermediateCA(caConfig *conf.ImCaConfig) error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	logger.Info("generate double intermediate CA", zap.Any("sign cert conf", signCertConf))
	err = genIntermediateCA(caConfig, db.SIGN, signCertConf.PrivateKeyPath)
	if err != nil {
		return err
	}
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	logger.Info("generate double intermediate CA", zap.Any("tls cert conf", tlsCertConf))
	err = genIntermediateCA(caConfig, db.TLS, tlsCertConf.PrivateKeyPath)
	if err != nil {
		return err
	}
	return nil
}

func genIntermediateCA(caConfig *conf.ImCaConfig, certUsage db.CertUsage, rootKeyPath string) error {
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	generatePrivateKey, generateKeyPair, err := CreateKeyPair(keyTypeStr, hashTypeStr, caConfig.PrivateKeyPwd)
	if err != nil {
		return err
	}
	csrRequestConf := createCsrReqConf(caConfig.CsrConf, generatePrivateKey)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		return err
	}
	certRequestConfig, err := createIMCACertReqConf(csrByte, certUsage, rootKeyPath)
	if err != nil {
		return err
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		return err
	}
	certConditions := &CertConditions{
		UserType:  db.INTERMRDIARY_CA,
		CertUsage: certUsage,
		UserId:    caConfig.CsrConf.CN,
		OrgId:     caConfig.CsrConf.O,
	}
	certInfo, err := CreateCertInfo(certContent, generateKeyPair.Ski, certConditions)
	if err != nil {
		return err
	}

	logger.Info("generate intermediate ca", zap.Any("cert info", certInfo))

	err = models.CreateCertTransaction(certContent, certInfo, generateKeyPair)
	if err != nil {
		return err
	}
	logger.Info("create intermediate ca successfully")
	return nil
}

func createCsrReqConf(csrConfig *conf.CsrConf, privateKey crypto.PrivateKey) *CSRRequestConfig {
	return &CSRRequestConfig{
		PrivateKey:         privateKey,
		Country:            csrConfig.Country,
		Locality:           csrConfig.Locality,
		Province:           csrConfig.Province,
		OrganizationalUnit: csrConfig.OU,
		Organization:       csrConfig.O,
		CommonName:         csrConfig.CN,
	}
}

func createIMCACertReqConf(csrByte []byte, certUsage db.CertUsage, rootKeyPath string) (*CertRequestConfig, error) {
	certInfo, err := models.FindCertInfo("", "", certUsage, db.ROOT_CA)
	if err != nil {
		return nil, err
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil {
		return nil, err
	}
	issuerPrivateKeyBytes, err := conf.ReadFile(rootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("create intermediate ca cert req config failed: %s", err.Error())
	}
	deCertContent := []byte(certContent.Content)
	issueprivateKey, err := ParsePrivateKey(issuerPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		return nil, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issueprivateKey,
		IssuerCertBytes:  deCertContent,
		ExpireYear:       int32(expireYearFromConfig()),
		CertUsage:        certUsage,
		UserType:         db.INTERMRDIARY_CA,
		CsrBytes:         csrByte,
	}

	return certRequestConfig, nil
}
