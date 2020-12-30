package services

import "chainmaker.org/wx-CRA-backend/utils"

//InitServer 初始化Ca
func InitServer() {
	isInitRootCa := utils.GetInitType()
	if isInitRootCa == true {
		InitRootCA()
		CreateIntermediariesCert()
	}
}
