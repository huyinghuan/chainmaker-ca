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

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
)

//CreatePrivKey create key pair
func createPrivKey(keyTypeStr string) (crypto.PrivateKey, error) {
	keyType, err := checkKeyType(keyTypeStr)
	if err != nil {
		return nil, err
	}
	privKey, err := asym.GenerateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("[create private key] generate key pair [%s] failed, %s", keyTypeStr, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey encrypt private key
func encryptPrivKey(privKey crypto.PrivateKey, privKeyPwd string, hashType crypto.HashType) ([]byte, []byte, error) {
	hashPwd, err := hash.Get(hashType, []byte(privKeyPwd))
	if err != nil {
		return nil, nil, fmt.Errorf("[encrypt] get pwd hash error: %s", err.Error())
	}
	//slice encryption of the key
	pwd := utils.DefaultPrivateKeyPwd + hex.EncodeToString(hashPwd)
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("[encrypt] private key to bytes failed: %s", err.Error())
	}
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, []byte(pwd), x509.PEMCipherAES256)
	if err != nil {
		return nil, nil, fmt.Errorf("[encrypt] x509 encrypt PEM block failed: %s", err.Error())
	}
	return pem.EncodeToMemory(privKeyPem), hashPwd, nil
}

//WritePrivKeyFile write private key to file
func WritePrivKeyFile(privKeyFilePath string, data []byte) error {
	dir, _ := path.Split(privKeyFilePath)
	err := CreateDir(dir)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(privKeyFilePath, data, os.ModePerm); err != nil {
		return fmt.Errorf("[write private key] write private key file failed: %s", err.Error())
	}
	return nil
}

//DecryptPrivKey decrypt private key
func decryptPrivKey(privKeyRaw []byte, hexHashPwd string, hashType crypto.HashType) (crypto.PrivateKey, error) {
	privatePwd := utils.DefaultPrivateKeyPwd + hexHashPwd
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, []byte(privatePwd))
	if err != nil {
		return nil, fmt.Errorf("[decrypt] asym private Key From PEM error: %s", err.Error())
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
	hashType, err := checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	if len(privateKeyPwd) == 0 {
		err = fmt.Errorf("[create key pair] private key pwd can't be empty")
		return
	}
	privKeyPemBytes, hashPwd, err = encryptPrivKey(privateKey, privateKeyPwd, hashType)
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
	return
}

func TransfToKeyPair(privateKeyPwd string, privateKeyBytes []byte) (keyPair *db.KeyPair, privateKey crypto.PrivateKey, err error) {
	var (
		hashType crypto.HashType
		keyType  crypto.KeyType
	)
	hashTypeStr := AllConfig.GetHashType()
	hashType, err = checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	hashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		err = fmt.Errorf("[parse private key] get hash pwd faield: %s", err.Error())
		return
	}
	keyTypeStr := AllConfig.GetKeyType()
	keyType, err = checkKeyType(keyTypeStr)
	if err != nil {
		return
	}
	privateKey, err = KeyBytesToPrivateKey(privateKeyBytes, hex.EncodeToString(hashPwd), hashType)
	if err != nil {
		return
	}
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("[parse private key] get private key ski failed: %s", err.Error())
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKey:     base64.StdEncoding.EncodeToString([]byte(publicKeyPEM)),
		PrivateKeyPwd: hex.EncodeToString(hashPwd),
		HashType:      hashType,
		KeyType:       keyType,
	}
	return
}
