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
