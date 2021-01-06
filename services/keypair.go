package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//CreatePrivKey 生成公私钥
func CreatePrivKey(keyType crypto.KeyType) (crypto.PrivateKey, error) {
	algoName, ok := crypto.KeyType2NameMap[keyType]
	if !ok {
		return nil, fmt.Errorf("unknown key algo type [%d]", keyType)
	}
	privKey, err := asym.GenerateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("generate key pair [%s] failed, %s", algoName, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey 加密私钥
func EncryptPrivKey(privKey crypto.PrivateKey, privKeyPwd []byte) ([]byte, error) {
	privKeyBytes, _ := privKey.Bytes()
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, privKeyPwd, x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("x509 EncryptPEMBlock failed: %s", err.Error())
	}
	return pem.EncodeToMemory(privKeyPem), nil
}

//WritePrivKeyFile 将密钥写入文件
func WritePrivKeyFile(privKeyFilePath string, data []byte) error {
	if err := ioutil.WriteFile(privKeyFilePath, data, os.ModePerm); err != nil {
		return fmt.Errorf("Write private key file failed: %s", err.Error())
	}
	return nil
}

//CreateKeyPairToDB 生成公私钥（可用KMS代替）
func CreateKeyPairToDB(caConifg *utils.CaConfig) (crypto.PrivateKey, error) {
	var keyPair db.KeyPair
	//生成公私钥（可对接KMS）
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	privKey, err := CreatePrivKey(keyType)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
		return nil, err
	}
	//私钥加密 密码:程序变量+读取密码
	privKeyPwd := DefaultPrivateKeyPwd + caConifg.PrivateKeyPwd
	hashPwd, err := hash.Get(hashType, []byte(privKeyPwd))
	if err != nil {
		logger.Error("Get private key pwd hash failed!", zap.Error(err))
		return nil, err
	}
	//私钥加密
	privKeyPemBytes, err := EncryptPrivKey(privKey, hashPwd)
	if err != nil {
		logger.Error("Private Encrypt failed!", zap.Error(err))
		return nil, err
	}
	//将加密后私钥写入文件
	err = WritePrivKeyFile(caConifg.PrivateKeyPath, privKeyPemBytes)
	if err != nil {
		logger.Error("Write privatekey failed!", zap.Error(err))
		return nil, err
	}

	//私钥入库
	keyPair.PrivateKey = privKeyPemBytes
	keyPair.PrivateKeyPwd = hex.EncodeToString(hashPwd)
	publicKeyBytes, _ := privKey.PublicKey().Bytes()
	keyPair.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLICKEY", Bytes: publicKeyBytes})
	keyPair.KeyType = keyType
	keyPair.UserID, err = models.GetCustomerIDByName(caConifg.Username)
	if err != nil {
		logger.Error("Get userid by username failed!", zap.Error(err))
		return nil, err
	}
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		logger.Error("Insert keypair failed!", zap.Error(err))
		return nil, err
	}
	return privKey, nil
}
