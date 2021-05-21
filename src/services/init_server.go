package services

import (
	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger
var allConfig *utils.AllConfig

//InitServer 初始化CA
func InitServer() {
	logger = loggers.GetLogger()
	allConfig = utils.GetAllConfig()
	err := CreateRootCa()
	if err != nil {
		logger.Error("[init] create root ca failed: %s", zap.Error(err))
		return
	}
	err = ProductIntermediateCA()
	if err != nil {
		logger.Error("[init] create intermediate ca failed: %s", zap.Error(err))
		return
	}
}
