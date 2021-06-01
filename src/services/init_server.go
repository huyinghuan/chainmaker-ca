package services

import (
	"fmt"

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
	if hashTypeFromConfig() == "SM3" && keyTypeFromConfig() != "SM2" || hashTypeFromConfig() != "SM3" && keyTypeFromConfig() == "SM2" {
		err := fmt.Errorf("the sm3 should be used with the sm2")
		logger.Error("init server failed", zap.Error(err))

	}
	err := CreateRootCa()
	if err != nil {
		logger.Error("init server failed", zap.Error(err))
		return
	}
	err = CreateIntermediateCA()
	if err != nil {
		logger.Error("init server failed", zap.Error(err))
		return
	}
}
