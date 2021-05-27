package models

type GenerateCertByCsrReq struct {
	OrgID     string `json:"orgID"`
	UserID    string `json:"userID"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	CsrBytes  []byte `json:"csrBytes"`
}

type GenCertReq struct {
	OrgID         string `json:"orgID"`
	UserID        string `json:"userID"`
	UserType      string `json:"userType"`
	CertUsage     string `json:"certUsage"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
}

type QueryCertReq struct {
	OrgID     string `json:"orgID"`
	UserID    string `json:"userID"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
}

type UpdateCertReq struct {
	CertSn int64 `json:"certSn"`
}

type RevokedCertReq struct {
	RevokedCertSn    int64  `json:"revokedcertSn"`
	IssueCertSn      int64  `json:"issuecertSn"`
	Reason           string `json:"reason"`
	RevokedStartTime int64  `json:"revokedStartTime"`
	RevokedEndTime   int64  `json:"revokedEndTime"`
}

type CrlListReq struct {
	IssueCertSn int64 `json:"issuecertSn"`
}
