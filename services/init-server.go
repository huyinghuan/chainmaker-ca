package services

import (
	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger

//InitServer 初始化Ca
func InitServer() {
	logger = loggers.GetLogger()
	isInitRootCa := utils.GetInitType()
	if isInitRootCa == true {
		InitRootCA()
		CreateIntermediateCert()
	}
}
