/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

//Service error response
func ServerErrorJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: SERVER_ERROR_RESP_CODE,
		Msg:  SERVER_ERROR_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

//Input error response
func InputErrorJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: INPUT_ERROR_RESP_CODE,
		Msg:  INPUT_ERROR_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

//Input empty response
func InputMissingJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: INPUT_MISSING_PESP_CODE,
		Msg:  INPUT_MISSING_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

//Successful response
func SuccessfulJSONResp(msg string, data interface{}, c *gin.Context) {
	resp := StandardResp{
		Code: SUCCESS_PESP_CODE,
		Msg:  SUCCESS_MSG,
		Data: data,
	}
	c.JSON(http.StatusOK, resp)
}

//Cors Cross-domain Cors
func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, token")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, token")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusAccepted)
		}
		c.Next()
	}
}
