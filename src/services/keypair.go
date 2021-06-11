/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

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
		privateKeyPem            string
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
		privateKeyPem = string(privKeyPemBytes)
	} else {
		privateKeyPem, _ = privateKey.String()
	}
	publicKeyPem, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("create key pair failed: %s", err.Error())
		return
	}
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    privateKeyPem,
		PublicKey:     publicKeyPem,
		PrivateKeyPwd: hexHashPwd,
		HashType:      utils.Name2HashTypeMap[hashTypeStr],
		KeyType:       crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	return
}

//CreateKeyPairNoEnc create key pair no encryption
func CreateKeyPairNoEnc(privateKeyTypeStr string, hashTypeStr string) (privateKey crypto.PrivateKey, keyPair *db.KeyPair, err error) {
	privateKey, err = createPrivKey(privateKeyTypeStr)
	if err != nil {
		return
	}
	hashType, err := checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	privateKeyPem, _ := privateKey.String()
	publicKeyPem, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("create key pair failed: %s", err.Error())
		return
	}
	keyPair = &db.KeyPair{
		Ski:           hex.EncodeToString(ski),
		PrivateKey:    privateKeyPem,
		PublicKey:     publicKeyPem,
		PrivateKeyPwd: "",
		HashType:      utils.Name2HashTypeMap[hashTypeStr],
		KeyType:       crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	return
}

//Convert the password and privatekey bytes to keypair and privatekey
func ConvertToKeyPair(privateKeyBytes []byte) (keyPair *db.KeyPair, privateKey crypto.PrivateKey, err error) {
	var (
		hashType crypto.HashType
		keyType  crypto.KeyType
	)
	hashTypeStr := hashTypeFromConfig()
	hashType, err = checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	keyTypeStr := keyTypeFromConfig()
	keyType, err = checkKeyType(keyTypeStr)
	if err != nil {
		return
	}
	privateKey, err = ParsePrivateKey(privateKeyBytes)
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
		PrivateKey:    string(privateKeyBytes),
		PublicKey:     publicKeyPEM,
		PrivateKeyPwd: "",
		HashType:      hashType,
		KeyType:       keyType,
	}
	return
}
