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
	csrRequest.OrgId = "org2"
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
		OrgID:     "org7",
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
		CertUsage:     "tls-enc",
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

func TestQueryCert(t *testing.T) {
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

func TestQueryCertByStatus(t *testing.T) {
	InitDB()
	InitServer()
	queryCertByStatusReq := &models.QueryCertByStatusReq{
		OrgID:      "org2",
		UserID:     "org2_2",
		UserType:   "admin",
		CertUsage:  "sign",
		CertStatus: "EXPIRED",
	}
	certContentList, err := QueryCertByStatus(queryCertByStatusReq)
	if err != nil {
		fmt.Print("no cert you want ", zap.Error(err))
	}
	fmt.Println("find the cert")
	for index, _ := range certContentList {
		fmt.Printf("这个是%d\n", index)
		//fmt.Println(value)
	}
}

func TestUpdateCert(t *testing.T) {
	InitDB()
	InitServer()
	updateCertReq := &models.UpdateCertReq{
		CertSn: 806294,
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
