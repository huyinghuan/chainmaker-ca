package models

import "chainmaker.org/wx-CRA-backend/models/db"

//ApplyCertReq .
type ApplyCertReq struct {
	PrivateKeyID string   `json:"privateKeyID"`
	Country      string   `json:"country"`
	Locality     string   `json:"locality"`
	Province     string   `json:"province"`
	ExpireYear   int32    `json:"expire_year"`
	NodeSans     []string `json:"nodeSans"`
}

//GenerateKeyPairReq .
type GenerateKeyPairReq struct {
	UserType      db.UserType  `json:"userType"`
	CertUsage     db.CertUsage `json:"certUsage"`
	UserID        string       `json:"userID"`
	OrgID         string       `json:"orgID"`
	ChainID       string       `json:"chainID"`
	PrivateKeyPwd string       `json:"privateKeyPwd"`
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
	ChainID    string `json:"chainID"`
	Filetarget string `json:"filetarget"` //证书生成路径
}

//Org 组织
type Org struct {
	AdminUserID string   `json:"adminUserID"`
	OrgID       string   `json:"orgID"`
	Country     string   `json:"country"`
	Locality    string   `json:"locality"`
	Province    string   `json:"province"`
	Nodes       []Node   `json:"nodes"`
	Users       []string `json:"users"`
}

//Node 节点
type Node struct {
	NodeID string   `json:"nodeID"`
	Sans   []string `json:"sans"`
}

//GetTarCertFileReq .
type GetTarCertFileReq struct {
	Filetarget string `json:"filetarget"`
	Filesource string `json:"filesource"`
}
