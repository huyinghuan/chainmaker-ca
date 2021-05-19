package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
)

//CreatePrivKey create key pair
func createPrivKey(keyTypeStr string) (crypto.PrivateKey, error) {
	keyType, err := utils.GetPrivateKeyType(keyTypeStr)
	if err != nil {
		return nil, err
	}
	privKey, err := asym.GenerateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("[Create private key] generate key pair [%s] failed, %s", keyTypeStr, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey encrypt private key
func encryptPrivKey(privKey crypto.PrivateKey, privKeyPwd []byte) ([]byte, error) {
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("[Encrypt PrivKey] private key to bytes failed: %s", err.Error())
	}
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, privKeyPwd, x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("[Encrypt PrivKey] x509 encrypt PEM block failed: %s", err.Error())
	}
	return pem.EncodeToMemory(privKeyPem), nil
}

//WritePrivKeyFile write private key to file
func WritePrivKeyFile(privKeyFilePath string, data []byte) error {
	dir, _ := path.Split(privKeyFilePath)
	err := CreateDir(dir)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(privKeyFilePath, data, os.ModePerm); err != nil {
		return fmt.Errorf("[Write Private key] write private key file failed: %s", err.Error())
	}
	return nil
}

//DecryptPrivKey decrypt private key
func decryptPrivKey(privKeyRaw []byte, privKeyPwd string, hashType crypto.HashType) (crypto.PrivateKey, error) {
	privateKeyPwd := utils.DefaultPrivateKeyPwd + privKeyPwd
	issureHashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		return nil, fmt.Errorf("[Decrypt PrivKey] get issue pwd error: %s", err.Error())
	}
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, issureHashPwd)
	if err != nil {
		return nil, fmt.Errorf("[Decrypt PrivKey] asym private Key From PEM error: %s", err.Error())
	}
	return issuerPrivKey, nil
}

//CreateKeyPair create key pair and storage into db
func CreateKeyPair(privateKeyTypeStr string, hashTypeStr string, privateKeyPwd string) (privateKey crypto.PrivateKey, keyPair *db.KeyPair, err error) {

	privateKey, err = createPrivKey(privateKeyTypeStr)
	if err != nil {
		return
	}
	var privKeyPemBytes, hashPwd []byte
	hashType, err := utils.GetHashType(hashTypeStr)
	if err != nil {
		return
	}
	if len(privateKeyPwd) == 0 {
		err = fmt.Errorf("[create key pair] private key pwd can't be empty")
		return
	}
	hashPwd, err = hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		err = fmt.Errorf("[create key pair] get pwd hash error: %s", err.Error())
		return
	}
	//slice encryption of the key
	pwd := utils.DefaultPrivateKeyPwd + hex.EncodeToString(hashPwd)

	privKeyPemBytes, err = encryptPrivKey(privateKey, []byte(pwd))
	if err != nil {
		return
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("[create key pair] compute ski failed: %s", err.Error())
		return
	}
	//key pair into db
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    base64.StdEncoding.EncodeToString(privKeyPemBytes),
		PublicKey:     base64.StdEncoding.EncodeToString([]byte(publicKeyPEM)),
		PrivateKeyPwd: hex.EncodeToString(hashPwd),
		HashType:      utils.Name2HashTypeMap[hashTypeStr],
		KeyType:       crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	err = models.InsertKeyPair(keyPair)
	if err != nil {
		return
	}
	return
}
