/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

type GenCertByCsrReq struct {
	OrgId     string
	UserId    string
	UserType  db.UserType
	CertUsage db.CertUsage
	CsrBytes  []byte
}

type GenCertReq struct {
	OrgId         string
	UserId        string
	UserType      db.UserType
	CertUsage     db.CertUsage
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}

type QueryCertsReq struct {
	OrgId     string
	UserId    string
	UserType  string
	CertUsage string
}

type RenewCertReq struct {
	CertSn int64
}

type RevokeCertReq struct {
	RevokedCertSn int64
	IssueCertSn   int64
	Reason        string
}

type GenCrlReq struct {
	IssueCertSn int64
}

type GenCsrReq struct {
	OrgId         string
	UserId        string
	UserType      db.UserType
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}

type CertAndPrivateKey struct {
	Cert       string `json:"cert"`
	PrivateKey string `json:"privateKey"`
}

type CertInfos struct {
	UserId      string `json:"userId"`
	OrgId       string `json:"orgId"`
	UserType    string `json:"userType"`
	CertUsage   string `json:"certUsage"`
	CertStatus  string `json:"certStatus"`
	CertSn      int64  `json:"certSn"`
	CertContent string `json:"certContent"`
	InvalidDate int64  `json:"invalidDate"`
}
