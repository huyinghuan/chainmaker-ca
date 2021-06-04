/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

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
		return nil, fmt.Errorf("generate key pair [%s] failed, %s", keyTypeStr, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey encrypt private key
func encryptPrivKey(privKey crypto.PrivateKey, hashPwd string) ([]byte, error) {
	//slice encryption of the key
	pwd := utils.DefaultPrivateKeyPwd + hashPwd
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encrypt private key failed: %s", err.Error())
	}
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, []byte(pwd), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key failed: %s", err.Error())
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
		return fmt.Errorf("write private key file failed: %s", err.Error())
	}
	return nil
}

//DecryptPrivKey decrypt private key
func decryptPrivKey(privKeyRaw []byte, hashPwd string) (crypto.PrivateKey, error) {
	privatePwd := utils.DefaultPrivateKeyPwd + hashPwd
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, []byte(privatePwd))
	if err != nil {
		return nil, fmt.Errorf("decrypt private Key from PEM failed: %s", err.Error())
	}
	return issuerPrivKey, nil
}

//CreateKeyPair create key pair
func CreateKeyPair(privateKeyTypeStr string, hashTypeStr string, privateKeyPwd string) (privateKey crypto.PrivateKey, keyPair *db.KeyPair, err error) {
	privateKey, err = createPrivKey(privateKeyTypeStr)
	if err != nil {
		return
	}
	hashType, err := checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	var (
		privKeyPemBytes, hashPwd []byte
		hexHashPwd               string
	)
	if isKeyEncryptFromConfig() {
		if len(privateKeyPwd) == 0 {
			err = fmt.Errorf("create key pair failed: private key pwd can't be empty")
			return
		}
		hashPwd, err = hash.Get(hashType, []byte(privateKeyPwd))
		if err != nil {
			return
		}
		privKeyPemBytes, err = encryptPrivKey(privateKey, string(hashPwd))
		if err != nil {
			return
		}
		hexHashPwd = hex.EncodeToString(hashPwd)
	} else {
		privateKeyPem, _ := privateKey.String()
		privKeyPemBytes = []byte(privateKeyPem)
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("create key pair failed: %s", err.Error())
		return
	}
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    base64.StdEncoding.EncodeToString(privKeyPemBytes),
		PublicKey:     base64.StdEncoding.EncodeToString([]byte(publicKeyPEM)),
		PrivateKeyPwd: hexHashPwd,
		HashType:      utils.Name2HashTypeMap[hashTypeStr],
		KeyType:       crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	return
}

//Converts the password and privatekey bytes to keypair and privatekey
func TransfToKeyPair(privateKeyPwd string, privateKeyBytes []byte) (keyPair *db.KeyPair, privateKey crypto.PrivateKey, err error) {
	var (
		hashType   crypto.HashType
		keyType    crypto.KeyType
		hexHashPwd string
	)
	hashTypeStr := hashTypeFromConfig()
	hashType, err = checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	hashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	if err != nil {
		err = fmt.Errorf("transfer private key to key pair failed: %s", err.Error())
		return
	}
	if isKeyEncryptFromConfig() {
		hexHashPwd = hex.EncodeToString(hashPwd)
	}

	keyTypeStr := keyTypeFromConfig()
	keyType, err = checkKeyType(keyTypeStr)
	if err != nil {
		return
	}
	privateKey, err = KeyBytesToPrivateKey(privateKeyBytes, string(hashPwd))
	if err != nil {
		return
	}
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("transfer private key to key pair failed: %s", err.Error())
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKey:     base64.StdEncoding.EncodeToString([]byte(publicKeyPEM)),
		PrivateKeyPwd: hexHashPwd,
		HashType:      hashType,
		KeyType:       keyType,
	}
	return
}
