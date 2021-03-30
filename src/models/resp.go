package models

const (
	SUCCESS_PESP_CODE = 200
	FAILED_RESP_CODE  = 500
)

type StandardResp struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

type CertInfo struct {
	PrivateKeyType string `json:"PrivateKeyType"`
	HashType       int    `json:"HashType"`
	Length         int    `json:"Length"`
	CertResp
}

type CertResp struct {
	OrgId       string `json:"org_id"`
	InvalidDate int64  `json:"invalid_date"`
	UserStatus  int    `json:"user_status"`
	Id          int    `json:"id"`
	OU          string `json:"ou"`
	UserType    string `json:"user_type"`
	CertType    int    `json:"cert_type"`
	CertSN      int64  `json:"cert_sn"`
}
