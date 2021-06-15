/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"
	"testing"

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
	generateCertByCsrReq := &GenCertByCsrReq{
		OrgId:     "org",
		UserId:    "default",
		UserType:  db.USER_ADMIN,
		CertUsage: db.SIGN,
		CsrBytes:  csrByte,
	}
	cerContent, err := GenCertByCsr(generateCertByCsrReq)
	if err != nil {
		fmt.Print("Generate Cert By Csr failed ", err.Error())
	}
	fmt.Print(cerContent)
}

func TestGenCert(t *testing.T) {
	InitDB()
	InitServer()
	genCertReq := &GenCertReq{
		OrgId:         "org2",
		UserId:        "default",
		UserType:      db.USER_ADMIN,
		CertUsage:     db.TLS_ENC,
		PrivateKeyPwd: "123456",
		Country:       "China",
		Locality:      "HaIdian",
		Province:      "Beijing",
	}
	cerContentAndprivateKey, err := GenCert(genCertReq)
	if err != nil {
		fmt.Print("Generate Cert failed", err.Error())
	}
	fmt.Println(cerContentAndprivateKey.Cert)
	fmt.Print(cerContentAndprivateKey.PrivateKey)
}
func TestQueryCertByStatus(t *testing.T) {
	InitDB()
	InitServer()
	queryCertByStatusReq := &QueryCertsReq{
		OrgId:     "org2",
		UserId:    "org2_2",
		UserType:  "admin",
		CertUsage: "sign",
	}
	certContentList, err := QueryCerts(queryCertByStatusReq)
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
	updateCertReq := &RenewCertReq{
		CertSn: 806294,
	}
	cetContent, err := RenewCert(updateCertReq)
	if err != nil {
		fmt.Print("update failed ", err.Error())
	}
	fmt.Print(cetContent)
}

func TestRevokedCert(t *testing.T) {
	InitDB()
	InitServer()
	revokedCertReq := &RevokeCertReq{
		RevokedCertSn: 480460,
		IssuerCertSn:  0,
		Reason:        "",
	}
	crl, err := RevokeCert(revokedCertReq)
	if err != nil {
		fmt.Print("Revoked Cert failed ", err.Error())
	}
	fmt.Print(crl)
}
