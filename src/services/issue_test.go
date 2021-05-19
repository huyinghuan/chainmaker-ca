package services

import(
	"testing"
	"refect"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
)

//csr请求 -> csr配置 -> csr流文件 -> 用于cert的构建



func TestIssueCertificate(t *testing.T) {
	initDB()
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
	csrRequest.PrivateKey=privateKey
	csrRequest.Country="China"
	csrRequest.Locality="default"
	csrRequest.OrgId="default"
	csrRequest.Province="default"
	csrRequest.UserId="default"
	csrRequest.UserType=db.ROOT_CA
	
	//用BuildCSRReqConf获得CSRRequestConfig
	csrRequestConf:=BuildCSRReqConf(&csrRequest)
	//用createCSR获得csr流文件
	csrByte,err:=createCSR(csrRequestConf)
	if err!=nil{
		fmt.Print("createCSR byte failed")
	}


	//用csrByte构建CertRequestConfig假数据
	certRequestConf.HashType=20 //HASH_TYPE_SM3  
	certRequestConf.IssuerPrivateKey,err=createPrivKey("SM2")
	if err!=nil {
		fmt.Print("createPrivKey cert failed")
	}
	certRequestConf.CsrBytes=csrByte
	certRequestConf.IssuerCertBytes=
	certRequestConf.ExpireYear=2
	certRequestConf.CertUsage=db.SIGN
	certRequestConf.UserType=db.ROOT_CA



}
