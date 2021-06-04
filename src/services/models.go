/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

type GenerateCertByCsrReq struct {
	OrgID     string
	UserID    string
	UserType  db.UserType
	CertUsage db.CertUsage
	CsrBytes  []byte
}

type GenCertReq struct {
	OrgID         string
	UserID        string
	UserType      db.UserType
	CertUsage     db.CertUsage
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}

type QueryCertReq struct {
	OrgID     string
	UserID    string
	UserType  db.UserType
	CertUsage db.CertUsage
}

type QueryCertByStatusReq struct {
	OrgID      string
	UserID     string
	UserType   db.UserType
	CertUsage  db.CertUsage
	CertStatus db.CertStatus
}

type UpdateCertReq struct {
	CertSn int64
}

type RevokedCertReq struct {
	RevokedCertSn int64
	IssueCertSn   int64
	Reason        string
}

type CrlListReq struct {
	IssueCertSn int64
}

type CreateCsrReq struct {
	OrgID         string
	UserID        string
	UserType      db.UserType
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}
