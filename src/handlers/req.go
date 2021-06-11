/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

type GenCertByCsrReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	Csr       string `json:"csr"`
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
	IssuerCertSn  int64  `json:"issuerCertSn"`
	Reason        string `json:"reason"`
}

type GenCrlReq struct {
	IssuerCertSn int64 `json:"issuerCertSn"`
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
