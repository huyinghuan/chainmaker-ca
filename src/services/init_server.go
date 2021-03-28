package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger

//InitServer 初始化Ca
func InitServer() {
	logger = loggers.GetLogger()
	isInitRootCa := utils.GetInitType()
	if isInitRootCa == true {
		// InitRootCA()
		BaasInitRootCA()
		CreateIntermediateCert()
	}
}
