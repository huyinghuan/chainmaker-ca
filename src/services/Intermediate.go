/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"encoding/base64"
	"encoding/hex"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
)

//create intermediateCA which is written in the configuration file
func CreateIntermediateCA() error {
	if checkIntermediateCaConf() == nil {
		return nil
	}
	for i := 0; i < len(checkIntermediateCaConf()); i++ {
		if exsitIntermediateCA(getIMCaConf()[i]) {
			continue
		}
		err := createIntermediateCA(getIMCaConf()[i])
		if err != nil {
			return err
		}
	}
	return nil
}

//Check if intermediateCA already exists
func exsitIntermediateCA(caConfig *utils.CaConfig) bool {
	_, err := models.FindActiveCertInfoByConditions(caConfig.CsrConf.CN, caConfig.CsrConf.O, 0, db.INTERMRDIARY_CA)
	return err == nil
}

func createIntermediateCA(caConfig *utils.CaConfig) error {
	caType, err := getCaType()
	if err != nil {
		return err
	}
	if caType == utils.SINGLE_ROOT || caType == utils.SIGN || caType == utils.TLS {
		err := GenSingleIntermediateCA(caConfig, caType)
		if err != nil {
			return err
		}
	}
	if caType == utils.DOUBLE_ROOT {
		err := GenDoubleIntermediateCA(caConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

//Generate single root intermediateCA
func GenSingleIntermediateCA(caConfig *utils.CaConfig, caType utils.CaType) error {
	if caType == utils.TLS {
		err := genIntermediateCA(caConfig, db.TLS)
		if err != nil {
			return err
		}
	}
	err := genIntermediateCA(caConfig, db.SIGN)
	if err != nil {
		return err
	}
	return nil
}

//Generate double root intermediateCA
func GenDoubleIntermediateCA(caConfig *utils.CaConfig) error {
	err := genIntermediateCA(caConfig, db.SIGN)
	if err != nil {
		return err
	}
	err = genIntermediateCA(caConfig, db.TLS)
	if err != nil {
		return err
	}
	return nil
}
func genIntermediateCA(caConfig *utils.CaConfig, certUsage db.CertUsage) error {
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	generatePrivateKey, generateKeyPair, err := CreateKeyPair(keyTypeStr, hashTypeStr, caConfig.CertConf.PrivateKeyPwd)
	if err != nil {
		return err
	}
	csrRequestConf := createCsrReqConf(caConfig, generatePrivateKey)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		return err
	}
	certRequestConfig, err := createIMCACertReqConf(caConfig, csrByte, certUsage)
	if err != nil {
		return err
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		return err
	}
	certConditions := &CertConditions{
		UserType:   db.INTERMRDIARY_CA,
		CertUsage:  certUsage,
		UserId:     caConfig.CsrConf.CN,
		OrgId:      caConfig.CsrConf.O,
		CertStatus: db.ACTIVE,
	}
	certInfo, err := CreateCertInfo(certContent, generateKeyPair.Ski, certConditions)
	if err != nil {
		return err
	}
	err = models.CreateCertTransaction(certContent, certInfo, generateKeyPair)
	if err != nil {
		return err
	}
	return nil
}

func createCsrReqConf(caConfig *utils.CaConfig, privateKey crypto.PrivateKey) *CSRRequestConfig {
	return &CSRRequestConfig{
		PrivateKey:         privateKey,
		Country:            caConfig.CsrConf.Country,
		Locality:           caConfig.CsrConf.Locality,
		Province:           caConfig.CsrConf.Province,
		OrganizationalUnit: caConfig.CsrConf.OU,
		Organization:       caConfig.CsrConf.O,
		CommonName:         caConfig.CsrConf.CN,
	}
}

func createIMCACertReqConf(caConfig *utils.CaConfig, csrByte []byte, certUsage db.CertUsage) (*CertRequestConfig, error) {
	certInfo, err := models.FindActiveCertInfoByConditions("", "", certUsage, db.ROOT_CA)
	if err != nil {
		return nil, err
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil {
		return nil, err
	}
	issueKeyPair, err := models.FindKeyPairBySki(certInfo.PrivateKeyId)
	if err != nil {
		return nil, err
	}
	deCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, err
	}
	dePrivatKey, err := base64.StdEncoding.DecodeString(issueKeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	hashPwd, err := hex.DecodeString(issueKeyPair.PrivateKeyPwd)
	if err != nil {
		return nil, err
	}
	issueprivateKey, err := KeyBytesToPrivateKey(dePrivatKey, string(hashPwd))
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
