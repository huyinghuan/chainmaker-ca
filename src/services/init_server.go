/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"go.uber.org/zap"
)

var logger *zap.Logger
var allConfig *utils.AllConfig

//Init server
func InitServer() {
	logger = loggers.GetLogger()
	allConfig = utils.GetAllConfig()
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

func checkBaseConf() {
	if hashTypeFromConfig() == "SM3" && keyTypeFromConfig() != "SM2" || hashTypeFromConfig() != "SM3" && keyTypeFromConfig() == "SM2" {
		err := fmt.Errorf("the sm3 should be used with the sm2")
		panic(err)
	}
	if expireYearFromConfig() <= 0 {
		err := fmt.Errorf("the expire year in config format error")
		panic(err)
	}
	_, err := getCaType()
	if err != nil {
		panic(err)
	}
	if len(provideServiceFor()) == 0 {
		err := fmt.Errorf("the provide service for in config format error")
		panic(err)
	}
}
