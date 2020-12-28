package services

import (
	"chainmaker.org/wx-CRA-backend/loggers"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

var logger = loggers.GetLogger()

//InitRootCA 初始化根CA
func InitRootCA() {
	rootCaConfig, err := utils.GetRootCaConfig()
	if err != nil {
		logger.Error("Get Root Ca Config Failed!", zap.Error(err))
		return
	}
	//生成公私要钥

}
