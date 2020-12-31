package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
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
