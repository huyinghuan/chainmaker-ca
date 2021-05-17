package models

//CreateKeyPairReq .
type CreateKeyPairReq struct {
	OrgId          string `json:"orgId"`
	UserId         string `json:"userId"`
	UserType       string `json:"userType"`
	CertUsage      string `json:"certUsage"`
	PrivateKeyPwd  string `json:"privateKeyPwd"`
	IsGenerate     bool   `json:"isGenerate"`
	PrivateKeySign string `json:"privateKeySign"`
}

//GenKeyAndCSRReq
type GenKeyAndCSRReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	CertUsage     string `json:"certUsage"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
}

//GenCertByCSRReq
type GenCertByCSRReq struct {
	KeyPairId string `json:"keyPairId"`
	CsrBytes  []byte `json:"csr"`
}

//ApplyCertReq
type ApplyCertReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	CertUsage     string `json:"certUsage"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
}

//QueryCertReq .
type QueryCertReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
}

//UpdateCertReq .
type UpdateCertReq struct {
	CertSn int64 `json:"certSn"`
}

//RevokedCertReq
type RevokedCertReq struct {
	CertSn           int64  `json:"certSn"`
	Reason           string `json:"reason"`
	RevokedStartTime int64  `json:"revokedStartTime"`
	RevokedEndTime   int64  `json:"revokedEndTime"`
}

//GetCrlListReq
type GetCrlListReq struct {
	OrgId     string `json:"orgId"`
	CaType    string `json:"caType"`
	CertUsage string `json:"certUsage"`
}

//GetP2PNodeIdReq
type GetP2PNodeIdReq struct {
	OrgId    string `json:"orgId"`
	NodeId   string `json:"nodeId"`
	CertFile []byte `json:"certfile"`
}
