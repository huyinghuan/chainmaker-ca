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
func createPrivKey(keyType crypto.KeyType) (crypto.PrivateKey, error) {
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
func encryptPrivKey(privKey crypto.PrivateKey, privKeyPwd []byte) ([]byte, error) {
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
func CreateKeyPairToDB(caConifg *utils.CaConfig) (privKey crypto.PrivateKey, keyID string, err error) {
	var keyPair db.KeyPair
	//生成公私钥（可对接KMS）
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	privKey, err = createPrivKey(keyType)
	if err != nil {
		logger.Error("Generate private key failed!", zap.Error(err))
		return
	}
	//私钥加密 密码:程序变量+读取密码
	privKeyPwd := DefaultPrivateKeyPwd + caConifg.PrivateKeyPwd
	hashPwd, err := hash.Get(hashType, []byte(privKeyPwd))
	fmt.Println(hex.EncodeToString(hashPwd))
	if err != nil {
		logger.Error("Get private key pwd hash failed!", zap.Error(err))
		return
	}
	//私钥加密
	privKeyPemBytes, err := encryptPrivKey(privKey, hashPwd)
	if err != nil {
		logger.Error("Private Encrypt failed!", zap.Error(err))
		return
	}
	//将加密后私钥写入文件
	err = WritePrivKeyFile(caConifg.PrivateKeyPath, privKeyPemBytes)
	if err != nil {
		logger.Error("Write privatekey failed!", zap.Error(err))
		return
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
		return
	}
	keyPair.ID = Getuuid()
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		logger.Error("Insert keypair failed!", zap.Error(err))
		return
	}
	keyID = keyPair.ID
	return
}

//DecryptPrivKey 解密私钥
func decryptPrivKey(privKeyRaw []byte, privKeyPwd string, hashType crypto.HashType) (crypto.PrivateKey, error) {
	privateKeyPwd := DefaultPrivateKeyPwd + privKeyPwd
	issureHashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		logger.Error("Get issuer private key pwd hash failed!", zap.Error(err))
		return nil, err
	}
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, issureHashPwd)
	if err != nil {
		logger.Error("PrivateKey Decrypt  failed!", zap.Error(err))
		return nil, err
	}
	return issuerPrivKey, nil
}

//CreateUserKeyPair .
func CreateUserKeyPair(username string, IsNodeKey bool, nodeName ...string) (privKey crypto.PrivateKey, keyID string, err error) {
	keyType := crypto.Name2KeyTypeMap[utils.GetPrivKeyType()]
	privKey, err = createPrivKey(keyType)
	if err != nil {
		logger.Error("create user keypair failed!", zap.Error(err))
		return
	}
	privKeyBytes, _ := privKey.Bytes()
	var keyPair db.KeyPair
	keyPair.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATEKEY", Bytes: privKeyBytes})
	publicKeyBytes, _ := privKey.PublicKey().Bytes()
	keyPair.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "PUBLICKEY", Bytes: publicKeyBytes})
	keyPair.KeyType = keyType
	keyPair.UserID, err = models.GetCustomerIDByName(username)
	if IsNodeKey == true {
		keyPair.NodeName = nodeName[0]
	}
	if err != nil {
		logger.Error("get user id by user name failed!", zap.Error(err))
		return
	}
	keyPair.ID = Getuuid()
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		logger.Error("insert keypair to db failed!", zap.Error(err))
		return
	}
	keyID = keyPair.ID
	return
}
