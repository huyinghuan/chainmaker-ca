/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"
	"log"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

const (
	OrgId                  = "TestOrg1"
	UserId                 = "TestUser"
	UserType  db.UserType  = db.USER_ADMIN
	CertUsage db.CertUsage = db.TLS
	Country                = "CN"
	Locality               = "Beijing"
	Province               = "Beijing"
)

func TestGenCert(t *testing.T) {
	TestInit(t)
	req := &GenCertReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  UserType,
		CertUsage: CertUsage,
		Country:   Country,
		Locality:  Locality,
		Province:  Province,
	}
	certAndPirvateKey, err := GenCert(req)
	if err != nil {
		log.Fatalf("gen cert failed: %s", err.Error())
	}
	fmt.Printf("cert content: %s\n", certAndPirvateKey.Cert)
	fmt.Printf("private key: %s\n", certAndPirvateKey.PrivateKey)
}

func TestGenCsr(t *testing.T) {
	TestInit(t)
	req := &GenCsrReq{
		OrgId:    OrgId,
		UserId:   UserId,
		UserType: UserType,
		Country:  Country,
		Locality: Locality,
		Province: Province,
	}
	csrBytes, err := GenCsr(req)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	fmt.Println(string(csrBytes))
}

func TestGenCertByCsr(t *testing.T) {
	TestInit(t)
	req := &GenCsrReq{
		OrgId:    OrgId,
		UserId:   UserId,
		UserType: UserType,
		Country:  Country,
		Locality: Locality,
		Province: Province,
	}
	csrBytes, err := GenCsr(req)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	csrReq := &GenCertByCsrReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  UserType,
		CertUsage: CertUsage,
		CsrBytes:  csrBytes,
	}
	certContent, err := GenCertByCsr(csrReq)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	fmt.Printf(certContent)
}
