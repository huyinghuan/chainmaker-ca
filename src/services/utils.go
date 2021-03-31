package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultCountry            = "CN"
	defaultLocality           = "Beijing"
	defaultProvince           = "Beijing"
	defaultOrganizationalUnit = "ChainMaker"
	defaultOrganization       = "ChainMaker"
	defaultCommonName         = "chainmaker.org"
	defaultExpireYear         = 2
)

const (
	//DefaultPrivateKeyPwd 分片加密
	DefaultPrivateKeyPwd = "wxliuxinfeng"
	//DefaultCertOrgSuffix .
	DefaultCertOrgSuffix = ".chainmaker.org"
	//DefaultRootOrg .
	DefaultRootOrg = "wx-root"
)

var PrivateKeyType2NameMap = map[crypto.KeyType]string{
	crypto.AES:           "AES",
	crypto.SM4:           "SM4",
	crypto.RSA512:        "RSA",
	crypto.RSA1024:       "RSA",
	crypto.RSA2048:       "RSA",
	crypto.SM2:           "SM2",
	crypto.ECC_Secp256k1: "ECC",
	crypto.ECC_NISTP256:  "ECC",
	crypto.ECC_NISTP384:  "ECC",
	crypto.ECC_NISTP521:  "ECC",
	crypto.ECC_Ed25519:   "ECC",
}

var PublicKeyType2NameMap = map[crypto.KeyType]string{
	crypto.AES:           "aes",
	crypto.SM4:           "sm4",
	crypto.RSA512:        "rsa",
	crypto.RSA1024:       "rsa",
	crypto.RSA2048:       "rsa",
	crypto.SM2:           "sm2",
	crypto.ECC_Secp256k1: "ecdsa",
	crypto.ECC_NISTP256:  "ecdsa",
	crypto.ECC_NISTP384:  "ecdsa",
	crypto.ECC_NISTP521:  "ecdsa",
	crypto.ECC_Ed25519:   "ecdsa",
}

var HashType2NameMap = map[crypto.HashType]string{
	crypto.HASH_TYPE_SM3:      "SM3",
	crypto.HASH_TYPE_SHA256:   "SHA256",
	crypto.HASH_TYPE_SHA3_256: "SHA3_256",
}

func dealSANS(sans []string) ([]string, []net.IP) {

	var dnsName []string
	var ipAddrs []net.IP

	for _, san := range sans {
		ip := net.ParseIP(san)
		if ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsName = append(dnsName, san)
		}
	}

	return dnsName, ipAddrs
}

//WirteCertToFile 将证书写入文件
func WirteCertToFile(certPath string, x509certEncode []byte) error {
	dir, file := path.Split(certPath)
	err := CreateDir(dir)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, file))
	if err != nil {
		return fmt.Errorf("[Write cert to file] os create error: %s", err.Error())
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	return nil
}

//ParseCertificate Cert byte解析成证书
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	var (
		cert *bcx509.Certificate
		err  error
	)
	block, rest := pem.Decode(certBytes)
	if block == nil {
		cert, err = bcx509.ParseCertificate(rest)
	} else {
		cert, err = bcx509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("[Parse certificate] x509 parse cert error: %s", err.Error())
	}
	return bcx509.ChainMakerCertToX509Cert(cert)
}

//ParseCsr  CSR byte解析成CSR
func ParseCsr(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	csrBC, err := bcx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[Parse csr] parse certificate request error: %s", err.Error())
	}

	return bcx509.ChainMakerCertCsrToX509CertCsr(csrBC)
}

//Getuuid 获取UUID
func Getuuid() string {
	uuid := uuid.NewV4()
	return uuid.String()
}

//CreateDir 创建文件夹
func CreateDir(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("[Create dir] os mkdir all error: %s", err.Error())
			}
		} else {
			return fmt.Errorf("[Create dir] os stat error: %s", err.Error())
		}
	}
	return nil
}

//CheckOrgInfo 校验组织信息
func CheckOrgInfo(org *models.Org) error {
	if org.OrgID == "" {
		err := fmt.Errorf("[CheckOrgInfo] orgID  can't be empty")
		return err
	}
	if org.Country == "" {
		err := fmt.Errorf("[CheckOrgInfo] country can't be empty")
		return err
	}
	if org.Locality == "" {
		err := fmt.Errorf("[CheckOrgInfo] locality can't be empty")
		return err
	}
	if org.Province == "" {
		err := fmt.Errorf("[CheckOrgInfo] province can't be empty")
		return err
	}
	return nil
}

//GetCertByConditions .
func GetCertByConditions(userID, orgID string, usage db.CertUsage, userType ...db.UserType) ([]*db.CertAndPrivKey, error) {
	keyPairList, err := models.GetKeyPairByConditions(userID, orgID, usage, userType...)
	if err != nil {
		return nil, err
	}
	if len(keyPairList) == 0 {
		return nil, nil
	}
	var certAndPrivKeys []*db.CertAndPrivKey
	for i := 0; i < len(keyPairList); i++ {
		var certAndPrivKey db.CertAndPrivKey
		cert, err := models.GetCertByPrivateKeyID(keyPairList[i].ID)
		if err != nil {
			return nil, err
		}
		certAndPrivKey.Cert = cert
		hashType := cert.HashType
		var isKms bool
		if utils.GetGenerateKeyPairType() && (keyPairList[i].UserType == db.USER_USER) && keyPairList[i].CertUsage == db.SIGN {
			isKms = true
		}
		privateKey, err := decryptPrivKey(keyPairList[i].PrivateKey, keyPairList[i].PrivateKeyPwd, hashType, isKms)
		if err != nil {
			return nil, err
		}
		certAndPrivKey.KeyPair = &keyPairList[i]
		certAndPrivKey.PrivKey = privateKey
		certAndPrivKeys = append(certAndPrivKeys, &certAndPrivKey)
	}

	return certAndPrivKeys, nil
}
