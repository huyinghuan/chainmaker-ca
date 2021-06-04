/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

type GenCertByCsrReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	CsrBytes  []byte `json:"csrBytes"`
}

type GenCertReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	CertUsage     string `json:"certUsage"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
}

type QueryCertReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
}

type QueryCertByStatusReq struct {
	OrgId      string `json:"orgId"`
	UserId     string `json:"userId"`
	UserType   string `json:"userType"`
	CertUsage  string `json:"certUsage"`
	CertStatus string `json:"certStatus"`
}

type RenewCertReq struct {
	CertSn int64 `json:"certSn"`
}

type RevokeCertReq struct {
	RevokedCertSn int64  `json:"revokedCertSn"`
	IssueCertSn   int64  `json:"issueCertSn"`
	Reason        string `json:"reason"`
}

type GenCrlReq struct {
	IssueCertSn int64 `json:"issueCertSn"`
}

type GenCsrReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
}
