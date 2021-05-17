package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger

//InitServer 初始化CA
func InitServer() {
	logger = loggers.GetLogger()
	isInitRootCa := utils.GetInitType()
	if isInitRootCa == true {
		InitRootCA()
	} else {
		LoadRootCAFromConfig()
	}
}
