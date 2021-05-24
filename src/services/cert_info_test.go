package services

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func TestCreateCertInfo(t *testing.T) {
	InitDB()
	//构建RootCertRequestConfig假数据
	var rootCertConf RootCertRequestConfig
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	privateKeyTypeStr = "SM2"
	hashTypeStr = "SM3"
	privateKeyPwd = "123456"
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
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

	certContent, err := IssueCertBySelf(&rootCertConf)
	if err != nil {
		fmt.Print("Issue Cert By Self failed")
	}

	//构建certconditions
	var certConditions CertConditions
	certConditions.UserType = db.ROOT_CA
	certConditions.CertUsage = db.SIGN
	certConditions.UserId = "default"
	certConditions.OrgId = "default"

	//测试函数
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, &certConditions)
	if err != nil {
		fmt.Println("Create Cert Info failed:")
		fmt.Print(err)
		return
	}
	fmt.Printf("SerialNumber=%d", certInfo.SerialNumber)
}
