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

	"chainmaker.org/chainmaker-go/common/crypto/tencentcloudkms"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/hash"
	"go.uber.org/zap"
)

//CreatePrivKey 生成公私钥
func createPrivKey(keyType crypto.KeyType, isKms bool, keyAlias string) (crypto.PrivateKey, error) {
	if isKms == true {
		kmsConfig, kmsKeyType := GetKmsConfig()
		client, err := tencentcloudkms.CreateConnection(kmsConfig)
		if err != nil {
			return nil, fmt.Errorf("[Create private key] create kms client connection error: %s", err.Error())
		}
		privKey, err := tencentcloudkms.GenerateKeyPairFromKMS(client, keyAlias, kmsKeyType)
		if err != nil {
			return nil, fmt.Errorf("[Create private key] generate keypair from kms error: %s", err.Error())
		}
		return privKey, nil
	}
	algoName, ok := crypto.KeyType2NameMap[keyType]
	if !ok {
		return nil, fmt.Errorf("[Create private key] unknown key algo type [%d]", keyType)
	}
	privKey, err := asym.GenerateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("[Create private key] generate key pair [%s] failed, %s", algoName, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey 加密私钥
func encryptPrivKey(privKey crypto.PrivateKey, privKeyPwd []byte) ([]byte, error) {
	privKeyBytes, _ := privKey.Bytes()
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, privKeyPwd, x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("[Encrypt PrivKey] x509 encrypt PEM block failed: %s", err.Error())
	}
	return pem.EncodeToMemory(privKeyPem), nil
}

//WritePrivKeyFile 将密钥写入文件
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

//DecryptPrivKey 解密私钥
func decryptPrivKey(privKeyRaw []byte, privKeyPwd string, hashType crypto.HashType, isKms bool) (crypto.PrivateKey, error) {
	if isKms == true {
		kmsConfig, _ := GetKmsConfig()
		client, err := tencentcloudkms.CreateConnection(kmsConfig)
		if err != nil {
			return nil, fmt.Errorf("[Decrypt PrivKey] get kms client failed,%s", err.Error())
		}
		privateKey, err := tencentcloudkms.LoadPrivateKey(client, privKeyRaw)
		if err != nil {
			return nil, fmt.Errorf("[Decrypt PrivKey] load private key failed,%s", err.Error())
		}
		return privateKey, nil
	}
	privateKeyPwd := DefaultPrivateKeyPwd + privKeyPwd
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

//CreateKeyPair .
func CreateKeyPair(privateKeyTypeStr string, hashTypeStr string, user *db.KeyPairUser, privateKeyPwd string, isKms bool) (privKey crypto.PrivateKey, keyID string, err error) {
	keyPairE, isKeyPairExist := models.KeyPairIsExistWithType(user.UserID, user.OrgID, hashTypeStr, user.CertUsage, user.UserType)
	if isKeyPairExist {
		hashType := crypto.HashAlgoMap[hashTypeStr]
		privateKey, err := decryptPrivKey(keyPairE.PrivateKey, keyPairE.PrivateKeyPwd, hashType, isKms)
		if err != nil {
			return nil, "", err
		}
		return privateKey, keyPairE.ID, nil
	}
	var keyPair db.KeyPair
	keyPair.ID = Getuuid()
	//生成公私钥（可对接KMS）
	keyType := crypto.Name2KeyTypeMap[privateKeyTypeStr]
	hashType := crypto.HashAlgoMap[hashTypeStr]
	privKey, err = createPrivKey(keyType, isKms, keyPair.ID)
	if err != nil {
		return
	}
	var privKeyPemBytes, hashPwd []byte
	//私钥加密 密码:程序变量+读取密码
	if privateKeyPwd != "" && isKms == false {
		privKeyPwd := DefaultPrivateKeyPwd + privateKeyPwd
		hashPwd, err = hash.Get(hashType, []byte(privKeyPwd))
		if err != nil {
			err = fmt.Errorf("[Create Key Pair] get pwd hash error: %s", err.Error())
			return
		}
		//私钥加密
		privKeyPemBytes, err = encryptPrivKey(privKey, hashPwd)
		if err != nil {
			return
		}
	} else {
		privKeyPEM, _ := privKey.String()
		privKeyPemBytes = []byte(privKeyPEM)
	}

	//私钥入库
	keyPair.PrivateKey = privKeyPemBytes
	keyPair.PrivateKeyPwd = hex.EncodeToString(hashPwd)
	publicKeyPEM, _ := privKey.PublicKey().String()
	keyPair.PublicKey = []byte(publicKeyPEM)
	keyPair.KeyType = keyType
	keyPair.CertUsage = user.CertUsage
	keyPair.UserType = user.UserType
	keyPair.OrgID = user.OrgID
	keyPair.UserID = user.UserID
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		return
	}
	keyID = keyPair.ID
	return
}

//GetKmsConfig .
func GetKmsConfig() (kmsConfig *tencentcloudkms.KMSConfig, kmsKeyType string) {
	config, err := utils.GetKmsClientConfig()
	if err != nil {
		logger.Error("get ksm config error", zap.Error(err))
	}
	kmsKeyType = utils.GetPrivKeyType()
	kmsConfig = &tencentcloudkms.KMSConfig{
		ServerAddress: config.KmsServer,
		ServerRegion:  config.KmsRegion,
		SecretId:      config.SecretID,
		SecretKey:     config.SecretKey,
	}
	return
}

// TODO hashType
//UploadKeyPair 上传公私钥
func UploadKeyPair(keyType string, user *db.KeyPairUser, privateKey []byte, privateKeyPwd string, isKms bool) (privKey crypto.PrivateKey, keyID string, err error) {

	//判断KeyType是否支持
	cryptoKey, ok := crypto.Name2KeyTypeMap[keyType]
	if !ok {
		return nil, "", fmt.Errorf("[Upload key pair] this key type is not support,[%s]", keyType)
	}
	keyPairE, isKeyPairExist := models.KeyPairIsExist(user.UserID, user.OrgID, user.CertUsage, user.UserType)
	if isKeyPairExist {
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		privateKey, err := decryptPrivKey(keyPairE.PrivateKey, keyPairE.PrivateKeyPwd, hashType, isKms)
		if err != nil {
			return nil, "", err
		}
		return privateKey, keyPairE.ID, nil
	}
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	privKey, err = decryptPrivKey(privateKey, privateKeyPwd, hashType, isKms)
	if err != nil {
		return
	}
	var keyPair db.KeyPair
	keyPair.ID = Getuuid()
	hashPwd, err := hash.Get(hashType, []byte(privateKeyPwd))
	//私钥入库
	keyPair.PrivateKey = privateKey
	publicKeyPEM, _ := privKey.PublicKey().String()
	keyPair.PublicKey = []byte(publicKeyPEM)
	keyPair.PrivateKeyPwd = hex.EncodeToString(hashPwd)
	keyPair.KeyType = cryptoKey
	keyPair.CertUsage = user.CertUsage
	keyPair.UserType = user.UserType
	keyPair.OrgID = user.OrgID
	keyPair.UserID = user.UserID
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		return
	}
	keyID = keyPair.ID
	return
}

//CreateRootKeyPair .
func CreateRootKeyPair(user *db.KeyPairUser, keyTypeStr string) (privKey crypto.PrivateKey, keyID string, err error) {
	//判断KeyType是否支持
	keyType, ok := crypto.Name2KeyTypeMap[keyTypeStr]
	if !ok {
		return nil, "", fmt.Errorf("[create root key pair] this key type is not support,[%s]", keyTypeStr)
	}
	keyPairE, isKeyPairExist := models.KeyPairIsExistWithType(user.UserID, user.OrgID, keyTypeStr, user.CertUsage, user.UserType)
	if isKeyPairExist {
		block, _ := pem.Decode(keyPairE.PrivateKey)
		privKey, err = asym.PrivateKeyFromDER(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("[create root key pair] private key from DER error: %s", err)
		}
		return privKey, keyPairE.ID, nil
	}
	var keyPair db.KeyPair
	keyPair.ID = Getuuid()
	privKey, err = createPrivKey(keyType, false, keyPair.ID)
	if err != nil {
		return
	}

	privKeyPEM, _ := privKey.String()
	privKeyPemBytes := []byte(privKeyPEM)

	//私钥入库
	keyPair.PrivateKey = privKeyPemBytes
	publicKeyPEM, _ := privKey.PublicKey().String()
	keyPair.PublicKey = []byte(publicKeyPEM)
	keyPair.KeyType = keyType
	keyPair.CertUsage = user.CertUsage
	keyPair.UserType = user.UserType
	keyPair.OrgID = user.OrgID
	keyPair.UserID = user.UserID
	err = models.InsertKeyPair(&keyPair)
	if err != nil {
		return
	}
	keyID = keyPair.ID

	//write private key by key type

	rootPrivateKeyPath, _ := utils.GetRootPrivateKey()
	rootPrivateKeyPath = rootPrivateKeyPath + "root-" + crypto.KeyType2NameMap[keyType] + ".key"
	err = WritePrivKeyFile(rootPrivateKeyPath, keyPair.PrivateKey)
	if err != nil {
		logger.Error("Init root ca error", zap.Error(err))
		return
	}
	return
}
