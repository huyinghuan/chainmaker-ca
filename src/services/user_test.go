package services

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"go.uber.org/zap"
)

func TestGenerateCertByCsr(t *testing.T) {
	InitDB()
	InitServer()
	var csrRequest CSRRequest
	//先createkeypair
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	privateKeyTypeStr = "ECC_NISTP256"
	hashTypeStr = "SHA256"
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
	csrRequest.OrgId = "org1"
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
	generateCertByCsrReq := &models.GenerateCertByCsrReq{
		OrgID:     "org1",
		UserID:    "default",
		UserType:  "admin",
		CertUsage: "sign",
		CsrBytes:  csrByte,
	}
	cerContent, err := GenerateCertByCsr(generateCertByCsrReq)
	if err != nil {
		fmt.Print("Generate Cert By Csr failed ", err.Error())
	}
	fmt.Print(cerContent)
}

func TestGenCert(t *testing.T) {
	InitDB()
	InitServer()
	genCertReq := &models.GenCertReq{
		OrgID:         "org2",
		UserID:        "default",
		UserType:      "admin",
		CertUsage:     "tls",
		PrivateKeyPwd: "123456",
		Country:       "China",
		Locality:      "Haidian",
		Province:      "Beijing",
	}
	cerContent, privateKey, err := GenCert(genCertReq)
	if err != nil {
		fmt.Print("Generate Cert failed", err.Error())
	}
	fmt.Println(cerContent)
	fmt.Print(privateKey)
}

func TestSearchCert(t *testing.T) {
	InitDB()
	InitServer()
	queryCertReq := &models.QueryCertReq{
		OrgID:     "org7",
		UserID:    "ca.org7",
		UserType:  "client",
		CertUsage: "sign",
	}
	certContent, err := QueryCert(queryCertReq)
	if err != nil {
		fmt.Print("no cert you want ", zap.Error(err))
	}
	fmt.Println("find the cert")
	fmt.Print(certContent)
}

func TestUpdateCert(t *testing.T) {
	InitDB()
	InitServer()
	updateCertReq := &models.UpdateCertReq{
		CertSn: 963474,
	}
	cetContent, err := UpdateCert(updateCertReq)
	if err != nil {
		fmt.Print("update failed ", err.Error())
	}
	fmt.Print(cetContent)
}

func TestRevokedCert(t *testing.T) {
	InitDB()
	InitServer()
	revokedCertReq := &models.RevokedCertReq{
		RevokedCertSn: 480460,
		IssueCertSn:   0,
	}
	crl, err := RevokedCert(revokedCertReq)
	if err != nil {
		fmt.Print("Revoked Cert failed ", err.Error())
	}
	fmt.Print(crl)
}
