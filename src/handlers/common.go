package handlers

import (
	"fmt"
	"net/http"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"github.com/gin-gonic/gin"
)

//FailedRespFunc .
func FailedRespFunc(msg, err string, c *gin.Context) {
	var resp models.StandardResp
	resp.Code = models.FAILED_RESP_CODE
	resp.Msg = msg
	resp.Data = err
	c.JSON(http.StatusOK, resp)
}

//SuccessfulJSONRespFunc .json的成功返回
func SuccessfulJSONRespFunc(msg string, data interface{}, c *gin.Context) {
	var resp models.StandardResp
	resp.Code = models.SUCCESS_PESP_CODE
	resp.Msg = msg
	resp.Data = data
	c.JSON(http.StatusOK, resp)
}

//SuccessfulFileRespFunc 文件流的返回
func SuccessfulFileRespFunc(fileName string, data []byte, c *gin.Context) {
	c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.Writer.Header().Add("Content-Type", "application/octet-stream")
	c.Data(http.StatusOK, "application/octet-stream", data)
}
