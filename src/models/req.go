package models

import "chainmaker.org/chainmaker-ca-backend/src/models/db"

//ApplyCertReq .
type ApplyCertReq struct {
	PrivateKeyID   string   `json:"privateKeyID"`
	Country        string   `json:"country"`
	Locality       string   `json:"locality"`
	Province       string   `json:"province"`
	ExpireYear     int32    `json:"expire_year"`
	NodeSans       []string `json:"nodeSans"`
	PrivateKeyType string   `json:"privateKeyType"`
	HashType       string   `json:"hashType"`
}

//GenerateKeyPairReq .
type GenerateKeyPairReq struct {
	UserType       db.UserType  `json:"userType"`
	CertUsage      db.CertUsage `json:"certUsage"`
	UserID         string       `json:"userID"`
	OrgID          string       `json:"orgID"`
	PrivateKeyPwd  string       `json:"privateKeyPwd"`
	PrivateKeyType string       `json:"privateKeyType"`
	HashType       string       `json:"hashType"`
}

//UpdateCertReq .
type UpdateCertReq struct {
	CertSN     int64 `json:"certSN"`
	ExpireYear int32 `json:"expire_year"`
}

//RevokedCertReq .
type RevokedCertReq struct {
	RevokedCertSN    int64  `json:"revokedCertSN"`
	Reason           string `json:"reason"`
	RevokedStartTime int64  `json:"revokedStartTime"`
	RevokedEndTime   int64  `json:"revokedEndTime"`
}

//ChainMakerCertApplyReq .
type ChainMakerCertApplyReq struct {
	Orgs       []Org  `json:"orgs"`
	Filetarget string `json:"filetarget"` //证书生成路径
}

//Org 组织
type Org struct {
	OrgID          string `json:"orgID"`
	Country        string `json:"country"`
	Locality       string `json:"locality"`
	Province       string `json:"province"`
	Nodes          []Node `json:"nodes"`
	Users          []User `json:"users"`
	PrivateKeyType string `json:"privateKeyType"`
	HashType       string `json:"hashType"`
}

//Node 节点
type Node struct {
	NodeID   string      `json:"nodeID"`
	NodeType db.UserType `json:"nodeType"`
	Sans     []string    `json:"sans"`
}

//User .
type User struct {
	UserName string      `json:"userName"`
	UserType db.UserType `json:"userType"`
}

//GetTarCertFileReq .
type GetTarCertFileReq struct {
	Filetarget string `json:"filetarget"`
	Filesource string `json:"filesource"`
}

//GetCertByConditionsReq .
type GetCertByConditionsReq struct {
	UserID    string       `json:"userID"` //nodeID/userName
	OrgID     string       `json:"orgID"`
	CertUsage db.CertUsage `json:"certUsage"`
	Type      db.UserType  `json:"type"`
}

type ApplyCertHadKeyPairReq struct {
	Country    string       `json:"country"`
	Locality   string       `json:"locality"`
	Province   string       `json:"province"`
	ExpireYear int32        `json:"expire_year"`
	NodeSans   []string     `json:"nodeSans"`
	UserType   db.UserType  `json:"userType"`
	CertUsage  db.CertUsage `json:"certUsage"`
	UserID     string       `json:"userID"`
	OrgID      string       `json:"orgID"`
}

//GetCertsReq .
type GetCertsReq struct {
	Page       int         `json:"Page"`
	PageSize   int         `json:"PageSize"`
	UserType   db.UserType `json:"UserType"`
	CertType   int         `json:"CertType"`
	UserStatus int         `json:"UserStatus"`
	OrgID      string      `json:"OrgID"`
	Id         int         `json:"Id"`
	StartTime  int64       `json:"StartTime"`
	EndTime    int64       `json:"EndTime"`
}
