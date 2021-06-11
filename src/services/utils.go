/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
)

//WirteCertToFile
func WirteFile(filePath string, fileBytes []byte) error {
	dir, _ := path.Split(filePath)
	err := CreateDir(dir)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, fileBytes, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//ParseCertificate.
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	var (
		cert *bcx509.Certificate
		err  error
	)
	block, rest := pem.Decode(certBytes)
	if block == nil {
		cert, err = bcx509.ParseCertificate(rest)
	} else {
		cert, err = bcx509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse x509 cert failed: %s", err.Error())
	}
	return bcx509.ChainMakerCertToX509Cert(cert)
}

//Convert privatekey byte to privatekey
func ParsePrivateKey(privateKeyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key from DER failed: %s", err.Error())
	}
	return privateKey, nil
}

//Convert privatekey byte to privatekey
func KeyBytesToPrivateKey(privateKeyBytes []byte, hashPwd string) (privateKey crypto.PrivateKey, err error) {
	if !isKeyEncryptFromConfig() {
		privateKey, err = ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return
		}
	}
	privateKey, err = decryptPrivKey(privateKeyBytes, hashPwd)
	if err != nil {
		return
	}
	return
}

//ParseCsr
func ParseCsr(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	csrBC, err := bcx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request failed: %s", err.Error())
	}

	return bcx509.ChainMakerCertCsrToX509CertCsr(csrBC)
}

//CreateDir create dir
func CreateDir(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create dir failed: %s", err.Error())
			}
		} else {
			return fmt.Errorf("create dir failed: %s", err.Error())
		}
	}
	return nil
}

//Convert extkeyusage to string
func ExtKeyUsageToString(extKeyUsage []x509.ExtKeyUsage) (string, error) {
	var extKeyUsageStr []string
	for _, v := range extKeyUsage {
		vStr := strconv.Itoa(int(v))
		extKeyUsageStr = append(extKeyUsageStr, vStr)
	}
	jsonBytes, err := json.Marshal(extKeyUsageStr)
	if err != nil {
		return "", fmt.Errorf("parse extKeyUsage to string faield: %s", err.Error())
	}
	return string(jsonBytes), nil
}

func checkKeyType(keyTypeStr string) (crypto.KeyType, error) {
	var (
		keyType crypto.KeyType
		ok      bool
	)
	if keyType, ok = crypto.Name2KeyTypeMap[keyTypeStr]; !ok {
		return keyType, fmt.Errorf("check key type failed: key type is unsupport!")
	}
	return keyType, nil
}

func checkHashType(hashTypeStr string) (crypto.HashType, error) {
	var (
		hashType crypto.HashType
		ok       bool
	)
	if hashType, ok = crypto.HashAlgoMap[hashTypeStr]; !ok {
		return hashType, fmt.Errorf("check hash type failed: hash type is unsupport!")
	}
	return hashType, nil
}

func checkIntermediateCaConf() []*utils.ImCaConfig {
	if len(imCaConfFromConfig()) == 0 {
		return nil
	}
	return imCaConfFromConfig()
}

func checkParamsOfCertReq(orgId, userId string, userType db.UserType, certUsage db.CertUsage) error {
	if userType != db.INTERMRDIARY_CA && len(userId) == 0 {
		return fmt.Errorf("check params of req failed: userId cannot be empty")
	}
	if userType == db.ROOT_CA {
		return fmt.Errorf("check params of req failed: cannot apply for a CA of type root")
	}
	if userType == db.INTERMRDIARY_CA && !canIssueCa() {
		return fmt.Errorf("check params of req failed: cannot continue to apply for a intermediate CA")
	}
	caType, err := getCaType()
	if err != nil {
		return err
	}

	if certUsage == db.TLS || certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN {
		if caType == utils.SIGN {
			return fmt.Errorf("check params of req failed: sign CA cannot issue a tls certificate")
		}
	}
	if certUsage == db.SIGN {
		if caType == utils.TLS {
			return fmt.Errorf("check params of req failed: tls CA cannot issue a sign certificate")
		}
	}

	orgGroup := provideServiceFor()
	for i := 0; i < len(orgGroup); i++ {
		if orgId == orgGroup[i] {
			return nil
		}
	}
	return fmt.Errorf("check params of req failed: the organization cannot be serviced")
}

//Check and transform usertype(string) ot db.UserType
func CheckParametersUserType(userTypeStr string) (db.UserType, error) {
	var (
		userType db.UserType
		ok       bool
	)
	if userType, ok = db.Name2UserTypeMap[userTypeStr]; !ok {
		err := fmt.Errorf("check user type failed: the user type does not meet the requirements")
		return userType, err
	}
	return userType, nil
}

func checkParametersCertUsage(certUsageStr string) (db.CertUsage, error) {
	var (
		certUsage db.CertUsage
		ok        bool
	)
	if certUsage, ok = db.Name2CertUsageMap[certUsageStr]; !ok {
		err := fmt.Errorf("check cert usage failed: the cert usage does not meet the requirements")
		return certUsage, err
	}
	return certUsage, nil
}

func getCaType() (utils.CaType, error) {
	var (
		caType utils.CaType
		ok     bool
	)
	if caType, ok = utils.Name2CaTypeMap[allConfig.GetCaType()]; !ok {
		return caType, fmt.Errorf("check ca type failed: ca type is unsupport!Currently supported types: [tls],[sign],[solo] or [double]")
	}
	return caType, nil
}

//Find the issuer through the orgid
func searchIssuerCa(orgId string, userType db.UserType, certUsage db.CertUsage) (issuerPrivateKey crypto.PrivateKey, issuerCertBytes []byte, err error) {
	caType, err := getCaType()
	if err != nil {
		return
	}
	issuerCertUsage := covertCertUsage(certUsage, caType)
	//Looking for an intermediate CA with the same orgid
	if userType == db.INTERMRDIARY_CA {
		return searchRootCa(issuerCertUsage)
	}
	var issuerCertInfo *db.CertInfo
	issuerCertInfo, err = models.FindActiveCertInfoByConditions("", orgId, issuerCertUsage, db.INTERMRDIARY_CA)
	if err != nil {
		if checkIntermediateCaConf() != nil {
			issuerCertInfo, err = models.FindActiveCertInfoByConditions("", "", issuerCertUsage, db.INTERMRDIARY_CA)
			if err != nil {
				return searchRootCa(issuerCertUsage)
			}
		} else {
			return searchRootCa(issuerCertUsage)
		}
	}
	var issuerCertContent *db.CertContent
	issuerCertContent, err = models.FindCertContentBySn(issuerCertInfo.SerialNumber)
	if err != nil {
		return
	}
	issuerCertBytes, err = base64.StdEncoding.DecodeString(issuerCertContent.Content)
	if err != nil {
		return
	}
	var issuerKeyPair *db.KeyPair
	issuerKeyPair, err = models.FindKeyPairBySki(issuerCertInfo.PrivateKeyId)
	if err != nil {
		return
	}
	var deIssuerPK []byte
	deIssuerPK, err = base64.StdEncoding.DecodeString(issuerKeyPair.PrivateKey)
	if err != nil {
		return
	}
	if isKeyEncryptFromConfig() {
		issuerPrivateKey, err = decryptPrivKey(deIssuerPK, issuerKeyPair.PrivateKeyPwd)
		if err != nil {
			return
		}
		return
	}
	issuerPrivateKey, err = ParsePrivateKey(deIssuerPK)
	if err != nil {
		return
	}
	return
}

func searchRootCa(certUsage db.CertUsage) (rootKey crypto.PrivateKey, rootCertBytes []byte, err error) {
	var rootCertContent *db.CertContent
	rootCertContent, err = models.FindActiveCertContentByConditions("", "", certUsage, db.ROOT_CA)
	if err != nil {
		return
	}
	rootCertBytes, err = base64.StdEncoding.DecodeString(rootCertContent.Content)
	if err != nil {
		return
	}
	var rootConf *utils.CertConf
	if certUsage == db.SIGN {
		rootConf, err = checkRootSignConf()
		if err != nil {
			return
		}
	}
	if certUsage == db.TLS {
		rootConf, err = checkRootTlsConf()
		if err != nil {
			return
		}
	}
	var issuerPrivateKeyBytes []byte
	issuerPrivateKeyBytes, err = ioutil.ReadFile(rootConf.PrivateKeyPath)
	if err != nil {
		return
	}
	rootKey, err = ParsePrivateKey(issuerPrivateKeyBytes)
	if err != nil {
		return
	}
	return
}

//Determine the CertUsage field of the CA you are looking for based on the startup mode and the one the user provided
func covertCertUsage(certUsage db.CertUsage, caType utils.CaType) db.CertUsage {
	if caType == utils.DOUBLE_ROOT {
		if certUsage == db.SIGN {
			return db.SIGN
		} else {
			return db.TLS
		}
	}
	if caType == utils.SINGLE_ROOT || caType == utils.SIGN {
		return db.SIGN
	}
	return db.TLS
}

//Get X509 certificate by sn
func GetX509Certificate(Sn int64) (*x509.Certificate, error) {
	certContent, err := models.FindCertContentBySn(Sn)
	if err != nil {
		return nil, err
	}
	certContentByte, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, err
	}
	certContentByteUse, err := ParseCertificate(certContentByte)
	if err != nil {
		return nil, err
	}
	return certContentByteUse, nil
}

func searchCertChain(certSn, issueSn int64) (bool, error) {
	if issueSn == 0 {
		return false, fmt.Errorf("can't search root cert chain")
	}
	certInfo, err := models.FindCertInfoBySn(certSn)
	if err != nil {
		return false, err
	}
	if certInfo.IssuerSn == issueSn {
		return true, nil
	}
	certSn = certInfo.IssuerSn
	if certSn == 0 {
		return false, nil
	}
	return searchCertChain(certSn, issueSn)
}

func checkCsrConf(csrConf *utils.CsrConf) error {
	if len(csrConf.Country) == 0 {
		csrConf.Country = DEFAULT_CSR_COUNTRIY
	}
	if len(csrConf.Locality) == 0 {
		csrConf.Locality = DEFAULT_CSR_LOCALITY
	}
	if len(csrConf.Province) == 0 {
		csrConf.Province = DEFAULT_CSR_PROVINCE
	}
	if _, ok := db.Name2UserTypeMap[csrConf.OU]; !ok {
		return fmt.Errorf("check the csr config failed: OU config is unsupported type")
	}
	if len(csrConf.O) == 0 {
		return fmt.Errorf("check the csr config failed: O can't be empty")
	}
	if len(csrConf.CN) == 0 {
		return fmt.Errorf("check the csr config failed: CN can't be empty")
	}
	return nil
}

func checkRootSignConf() (*utils.CertConf, error) {
	certConf := rootCertConfFromConfig()
	for _, v := range certConf {
		if v.CertType == "sign" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("the correct path to sign the cert was not found")
}

func checkRootTlsConf() (*utils.CertConf, error) {
	certConf := rootCertConfFromConfig()
	for _, v := range certConf {
		if v.CertType == "tls" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("the correct path to tls the cert was not found")
}
