package services

import (
	"encoding/base64"
	"fmt"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/crypto"
)

func TestIssueCertBySelf(t *testing.T) {
	InitDB()
	//构建RootCertRequestConfig假数据
	var rootCertConf RootCertRequestConfig
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	privateKeyTypeStr = "SM2"
	hashTypeStr = "SM3"
	privateKeyPwd = "123456"
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Print("Create KeyPair Error")
		return
	}
	rootCertConf.PrivateKey = privateKey
	rootCertConf.Country = "defalut"
	rootCertConf.Locality = "defalut"
	rootCertConf.Province = "defalut"
	rootCertConf.OrganizationalUnit = "defalut"
	rootCertConf.Organization = "defalut"
	rootCertConf.CommonName = "defalut"
	rootCertConf.ExpireYear = 2
	rootCertConf.CertUsage = db.SIGN
	rootCertConf.UserType = db.ROOT_CA
	rootCertConf.HashType = "SM3"

	_, err = IssueCertBySelf(&rootCertConf)
	if err != nil {
		fmt.Print("Issue Cert By Self failed")
	}
}

//csr请求 -> csr配置 -> csr流文件 -> 用于cert的构建
func TestIssueCertificate(t *testing.T) {
	InitDB()
	var certRequestConf CertRequestConfig
	var csrRequest CSRRequest
	//先createkeypair
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	privateKeyTypeStr = "SM2"
	hashTypeStr = "SM3"
	privateKeyPwd = "123456"
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Print("Create KeyPair Error")
		return
	}
	//构造数据csrRequest的假数据
	csrRequest.PrivateKey = privateKey
	csrRequest.Country = "China"
	csrRequest.Locality = "default"
	csrRequest.OrgId = "default"
	csrRequest.Province = "default"
	csrRequest.UserId = "default"
	csrRequest.UserType = db.USER_ADMIN

	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf := BuildCSRReqConf(&csrRequest)
	//用createCSR获得csr流文件
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		fmt.Print("createCSR byte failed")
	}

	//用csrByte构建CertRequestConfig假数据
	certRequestConf.HashType = crypto.HASH_TYPE_SM3 //HASH_TYPE_SM3
	certRequestConf.IssuerPrivateKey, err = createPrivKey("SM2")
	if err != nil {
		fmt.Print("createPrivKey cert failed")
	}
	certRequestConf.CsrBytes = csrByte
	certRequestConf.ExpireYear = 2
	certRequestConf.CertUsage = db.SIGN
	certRequestConf.UserType = db.USER_ADMIN
	//接着去拿一个证书流IssuerCertBytes文件 通过自签函数IssueCertBySelf 随便生成一个

	//构建RootCertRequestConfig假数据
	var rootCertConf RootCertRequestConfig
	rootCertConf.PrivateKey = privateKey
	rootCertConf.Country = "defalut"
	rootCertConf.Locality = "defalut"
	rootCertConf.Province = "defalut"
	rootCertConf.OrganizationalUnit = "defalut"
	rootCertConf.Organization = "defalut"
	rootCertConf.CommonName = "defalut"
	rootCertConf.ExpireYear = 2
	rootCertConf.CertUsage = db.SIGN
	rootCertConf.UserType = db.ROOT_CA
	rootCertConf.HashType = "SM3"

	certContent, err := IssueCertBySelf(&rootCertConf)
	if err != nil {
		fmt.Print("Issue Cert By Self failed")
	}
	//解码拿到证书流
	certRequestConf.IssuerCertBytes, err = base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		fmt.Print("Decode certContent failed")
	}
	//测试对应函数

	_, err = IssueCertificate(&certRequestConf)
	if err != nil {
		fmt.Print("Issue Certificate failed")
	}
}
