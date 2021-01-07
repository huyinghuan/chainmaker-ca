package models

//ApplyCertReq .
type ApplyCertReq struct {
	Country            string `json:"country"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organization_unit"`
	CommonName         string `json:"common_name"`
	ExpireYear         int32  `json:"expire_year"`
}

//UpdateCertReq .
type UpdateCertReq struct {
	CertID     int   `json:"certID"`
	ExpireYear int32 `json:"expire_year"`
}

//RevokedCertReq .
type RevokedCertReq struct {
	RevokedCertID    int    `json:"revokedCertId"`
	RevokedCertSN    int64  `json:"revokedCertSN"`
	Reason           string `json:"reason"`
	RevokedStartTime int64  `json:"revokedStartTime"`
	RevokedEndTime   int64  `json:"revokedEndTime"`
}
