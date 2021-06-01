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

type QueryCertResp struct {
	UserId      string `json:"userId"`
	OrgId       string `json:"orgId"`
	UserType    string `json:"userType"`
	CertUsage   string `json:"certUsage"`
	CertStatus  string `json:"certStatus"`
	CertSn      int64  `json:"certSn"`
	CertContent string `json:"certContent"`
	InvalidDate int64  `json:"invalidDate"`
}
