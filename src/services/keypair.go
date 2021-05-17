package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
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
func CreateKeyPair(privateKeyTypeStr string, hashTypeStr string, keyPairType *db.KeyPairType, privateKeyPwd string) (crypto.PrivateKey, string, error) {
	if keyPair := models.IsKeyPairExist(keyPairType.UserId, keyPairType.OrgId, keyPairType.CertUsage, keyPairType.UserType); keyPair != nil {
		if utils.IsEncryptedPrivatekey() {
			hashType := keyPair.HashType
			privateKey, err := decryptPrivKey(keyPair.PrivateKey, keyPair.PrivateKeyPwd, hashType)
			if err != nil {
				return nil, "", err
			}
			return privateKey, keyPair.Id, nil
		}
		privateKey, err := ParsePrivateKey(keyPair.PrivateKey)
		if err != nil {
			return nil, "", err
		}
		return privateKey, keyPair.Id, nil
	}

	privateKey, err := createPrivKey(privateKeyTypeStr)
	if err != nil {
		return nil, "", err
	}

	var privKeyPemBytes, hashPwd []byte
	//slice encryption of the key
	if utils.IsEncryptedPrivatekey() {
		privKeyPwd := utils.DefaultPrivateKeyPwd + privateKeyPwd
		hashType, err := utils.GetHashType(hashTypeStr)
		if err != nil {
			return nil, "", err
		}
		hashPwd, err = hash.Get(hashType, []byte(privKeyPwd))
		if err != nil {
			return nil, "", fmt.Errorf("[Create Key Pair] get pwd hash error: %s", err.Error())
		}
		privKeyPemBytes, err = encryptPrivKey(privateKey, hashPwd)
		if err != nil {
			return nil, "", err
		}
	} else {
		privKeyPEM, _ := privateKey.String()
		privKeyPemBytes = []byte(privKeyPEM)
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	var hexHashPwd string
	if len(hashPwd) != 0 {
		hexHashPwd = hex.EncodeToString(hashPwd)
	}

	//key pair into db
	keyPair := &db.KeyPair{
		Id:            Getuuid(),
		PrivateKey:    privKeyPemBytes,
		PublicKey:     []byte(publicKeyPEM),
		PrivateKeyPwd: hexHashPwd,
		HashType:      utils.Name2HashTypeMap[hashTypeStr],
		KeyType:       crypto.Name2KeyTypeMap[privateKeyTypeStr],
		UserType:      keyPairType.UserType,
		CertUsage:     keyPairType.CertUsage,
		OrgId:         keyPairType.OrgId,
		UserId:        keyPairType.UserId,
	}
	err = models.InsertKeyPair(keyPair)
	if err != nil {
		return nil, "", err
	}
	return privateKey, keyPair.Id, nil
}
