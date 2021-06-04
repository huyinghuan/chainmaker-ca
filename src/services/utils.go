/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"os"
	"path"
	"strconv"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	uuid "github.com/satori/go.uuid"
)

func dealSANS(sans []string) ([]string, []net.IP) {

	var dnsName []string
	var ipAddrs []net.IP

	for _, san := range sans {
		ip := net.ParseIP(san)
		if ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsName = append(dnsName, san)
		}
	}

	return dnsName, ipAddrs
}

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

//Getuuid get uuid
func Getuuid() string {
	uuid := uuid.NewV4()
	return uuid.String()
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

func getRootCaConf() *utils.CaConfig {
	return allConfig.GetRootConf()
}

func getIMCaConf() []*utils.CaConfig {
	return allConfig.GetIntermediateConf()
}

func getDoubleRootPathConf() *utils.DoubleRootPathConf {
	return allConfig.GetDoubleRootPathConf()
}

func canIssueCa() bool {
	return allConfig.GetCanIssueCa()
}

func provideServiceFor() []string {
	return allConfig.GetProvideServiceFor()
}
func hashTypeFromConfig() string {
	return allConfig.GetHashType()
}

func keyTypeFromConfig() string {
	return allConfig.GetKeyType()
}

func expireYearFromConfig() int {
	return allConfig.GetDefaultExpireTime()
}

func isKeyEncryptFromConfig() bool {
	return allConfig.IsKeyEncrypt()
}

func checkIntermediateCaConf() []*utils.CaConfig {
	if len(allConfig.GetIntermediateConf()) == 0 {
		return nil
	}
	return allConfig.GetIntermediateConf()
}

func checkParamsOfCertReq(orgID string, userType db.UserType, certUsage db.CertUsage) error {
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
		if orgID == orgGroup[i] {
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
func searchIssuedCa(orgID string, certUsage db.CertUsage) (crypto.PrivateKey, []byte, error) {
	caType, err := getCaType()
	if err != nil {
		return nil, nil, err
	}
	certUsage = covertCertUsage(certUsage, caType)
	//Looking for an intermediate CA with the same orgid
	certInfo, err := models.FindActiveCertInfoByConditions("", orgID, certUsage, 0)
	if err != nil || certInfo.UserType != db.INTERMRDIARY_CA { //去找rootca签
		certInfo, err = models.FindActiveCertInfoByConditions("", "", certUsage, db.ROOT_CA)
		if err != nil {
			return nil, nil, err
		}
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil {
		return nil, nil, err
	}
	keyPair, err := models.FindKeyPairBySki(certInfo.PrivateKeyId)
	if err != nil {
		return nil, nil, err
	}
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, nil, err
	}

	dePrivatKey, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	hashPwd, err := hex.DecodeString(keyPair.PrivateKeyPwd)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := KeyBytesToPrivateKey(dePrivatKey, string(hashPwd))
	if err != nil {
		return nil, nil, err
	}
	return privateKey, reCertContent, nil
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

//Read file
func ReadWithFile(file multipart.File) ([]byte, error) {
	var result []byte
	var tmp = make([]byte, 128)
	for {
		n, err := file.Read(tmp)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		result = append(result, tmp[:n]...)
	}
	return result, nil
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
