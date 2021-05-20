package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"go.uber.org/zap"
)

var logger *zap.Logger

//InitServer 初始化CA
func InitServer() {
	logger = loggers.GetLogger()
	err := CreateRootCa()
	if err != nil {
		logger.Error("[init] create root ca failed: %s", zap.Error(err))
		return
	}
}
