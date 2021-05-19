package services

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
)

func initDB() {
	utils.SetConfig(utils.GetConfigEnv())
	db.DBInit()
}

func TestCreateKeyPair(t *testing.T) {
	initDB()
	var privateKeyTypeStr string
	var hashTypeStr string
	var privateKeyPwd string
	privateKeyTypeStr = "SM2"
	hashTypeStr = "SM3"
	privateKeyPwd = "123456"
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Print("Create KeyPair Error")
		return
	}
	fmt.Print(privateKey)
	fmt.Print(keyPair)
}
