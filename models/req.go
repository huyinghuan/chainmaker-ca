package models

//ApplyCertReq .
type ApplyCertReq struct {
	CertType           string   `json:"certType"`
	ChainID            string   `json:"chainID"`
	ConsortiumID       string   `json:"consortiumID"`
	Country            string   `json:"country"`
	Locality           string   `json:"locality"`
	Province           string   `json:"province"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organization_unit"`
	CommonName         string   `json:"common_name"`
	ExpireYear         int32    `json:"expire_year"`
	NodeName           string   `json:"nodeName"`
	Sans               []string `json:"sans"`
	CertUsage          string   `json:"certUsage"`
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
	Orgs         []Org  `json:"orgs"`
	ChainID      string `json:"chainID"`
	ConsortiumID string `json:"consortiumID"`
}

//Org 组织
type Org struct {
	Username           string `json:"username"`
	Country            string `json:"country"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organization_unit"`
	CommonName         string `json:"common_name"`
	Nodes              []Node `json:"nodes"`
}

//Node 节点
type Node struct {
	NodeName string   `json:"nodeName"`
	Sans     []string `json:"sans"`
}
