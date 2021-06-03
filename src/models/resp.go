/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

const (
	SUCCESS_PESP_CODE       = 200
	INPUT_MISSING_PESP_CODE = 202
	INPUT_ERROR_RESP_CODE   = 204
	SERVER_ERROR_RESP_CODE  = 500
)

const (
	INPUT_MISSING_MSG = "Missing required parameters"
	INPUT_ERROR_MSG   = "There is an error in the input parameter"
	SERVER_ERROR_MSG  = "An error occurred with the internal service"
	SUCCESS_MSG       = "The request service returned successfully"
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
