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
