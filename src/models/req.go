package models

import "chainmaker.org/chainmaker-ca-backend/src/models/db"

type GenerateCertByCsrReq struct {
	OrgID     string       `json:"orgID"`
	UserID    string       `json:"userID"`
	UserType  db.UserType  `json:"userType"`
	CertUsage db.CertUsage `json:"certUsage"`
	CsrBytes  []byte       `json:"csrBytes"`
}

type GenCert struct {
	OrgID         string       `json:"orgID"`
	UserID        string       `json:"userID"`
	UserType      db.UserType  `json:"userType"`
	CertUsage     db.CertUsage `json:"certUsage"`
	PrivateKeyPwd string       `json:"privateKeyPwd"`
	Country       string       `json:"country"`
	Locality      string       `json:"locality"`
	Province      string       `json:"province"`
}
