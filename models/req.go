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
