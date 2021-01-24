package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"

	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
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
		return fmt.Errorf("create dir failed,%s", err.Error())
	}
	f, err := os.Create(filepath.Join(dir, file))
	if err != nil {
		return fmt.Errorf("create file failed, %s", err.Error())
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	return nil
}

//ParseCertificate Cert byte解析成证书
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	cert, err := bcx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificate cert failed, %s", err)
	}

	return bcx509.ChainMakerCertToX509Cert(cert)
}

//ParseCsr  CSR byte解析成CSR
func ParseCsr(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	csrBC, err := bcx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateRequest failed, %s", err)
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
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}

//CheckOrgInfo 校验组织信息
func CheckOrgInfo(org *models.Org) error {
	if org.OrgID == "" {
		err := fmt.Errorf("OrgID  can't be empty")
		return err
	}
	if org.Country == "" {
		err := fmt.Errorf("Country can't be empty")
		return err
	}
	if org.Locality == "" {
		err := fmt.Errorf("Locality can't be empty")
		return err
	}
	if org.Province == "" {
		err := fmt.Errorf("Province can't be empty")
		return err
	}
	return nil
}

//GetCertByConditions .
func GetCertByConditions(userID, orgID string, usage db.CertUsage, userType ...db.UserType) ([]*db.CertAndPrivKey, error) {
	keyPairList, err := models.GetKeyPairByConditions(userID, orgID, usage, userType...)
	if err != nil {
		return nil, fmt.Errorf("Get key pair by conditions failed: %s", err.Error())
	}
	if len(keyPairList) == 0 {
		return nil, nil
	}
	var certAndPrivKeys []*db.CertAndPrivKey
	for i:=0;i<len(keyPairList);i++{
		var certAndPrivKey db.CertAndPrivKey
		cert, err := models.GetCertByPrivateKeyID(keyPairList[i].ID)
		if err != nil {
			return nil, fmt.Errorf("Get cert by private key id failed: %s", err.Error())
		}
		certAndPrivKey.Cert = cert
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		var isKms bool
		if utils.GetGenerateKeyPairType() && (keyPairList[i].UserType == db.USER_ADMIN || keyPairList[i].UserType == db.USER_USER) && keyPairList[i].CertUsage == db.SIGN {
			isKms = true
		}
		privateKey, err := decryptPrivKey(keyPairList[i].PrivateKey, keyPairList[i].PrivateKeyPwd, hashType, isKms)
		if err != nil {
			return nil, fmt.Errorf("Decrypt private key failed: %s", err.Error())
		}
		certAndPrivKey.KeyPair = &keyPairList[i]
		certAndPrivKey.PrivKey = privateKey
		certAndPrivKeys = append(certAndPrivKeys, &certAndPrivKey)
	}

	return certAndPrivKeys, nil
}
