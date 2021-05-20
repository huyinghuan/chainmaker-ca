package services

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	uuid "github.com/satori/go.uuid"
)

var AllConfig *utils.AllConfig

func init() {
	AllConfig = utils.GetAllConfig()
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

//WirteCertToFile
func WirteFile(filePath string, fileBytes []byte) error {
	dir, _ := path.Split(filePath)
	err := CreateDir(dir)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, fileBytes, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//ParseCertificate.
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

func ParsePrivateKey(privateKeyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[Parse private key] asym parse private key from DER error: %s", err.Error())
	}
	return privateKey, nil
}

//ParseCsr
func ParseCsr(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	csrBC, err := bcx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[Parse csr] parse certificate request error: %s", err.Error())
	}

	return bcx509.ChainMakerCertCsrToX509CertCsr(csrBC)
}

//Getuuid get uuid
func Getuuid() string {
	uuid := uuid.NewV4()
	return uuid.String()
}

//CreateDir create dir
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

func ExtKeyUsageToString(extKeyUsage []x509.ExtKeyUsage) (string, error) {
	var extKeyUsageStr []string
	for _, v := range extKeyUsage {
		vStr := strconv.Itoa(int(v))
		extKeyUsageStr = append(extKeyUsageStr, vStr)
	}
	jsonBytes, err := json.Marshal(extKeyUsageStr)
	if err != nil {
		return "", fmt.Errorf("parse extKeyUsage to string faield: %s", err.Error())
	}
	return string(jsonBytes), nil
}

func checkKeyType(keyTypeStr string) (crypto.KeyType, error) {
	var (
		keyType crypto.KeyType
		ok      bool
	)
	if keyType, ok = crypto.Name2KeyTypeMap[keyTypeStr]; !ok {
		return keyType, fmt.Errorf("[check] key type is unsupport!")
	}
	return keyType, nil
}

func checkHashType(hashTypeStr string) (crypto.HashType, error) {
	var (
		hashType crypto.HashType
		ok       bool
	)
	if hashType, ok = crypto.HashAlgoMap[hashTypeStr]; !ok {
		return hashType, fmt.Errorf("[check] hash type is unsupport!")
	}
	return hashType, nil
}

func canIssueCa() bool {
	return AllConfig.GetCanIssueCa()
}

func provideServiceFor() []string {
	return AllConfig.GetProvideServiceFor()
}
func hashTypeFromConfig() string {
	return AllConfig.GetHashType()
}
func expireYearFromConfig() int {
	return AllConfig.GetDefaultExpireTime()
}

func whetherOrNotProvideService(orgID string, certUsage db.CertUsage) bool {
	if canIssueCa() {
		caType, _ := getCaType()
		if certUsage == db.SIGN || certUsage == db.TLS_SIGN {
			if caType == utils.TLS {
				return false
			}
		}
		if certUsage == db.TLS || certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN {
			if caType == utils.SIGN {
				return false
			}
		}
		orgGroup := provideServiceFor()
		for i := 0; i < len(orgGroup); i++ {
			if orgID == orgGroup[i] {
				return true
			}
		}
	}
	return false
}

//检查一些参数的合法性
func checkParametersUserType(userType db.UserType) error {
	if _, ok := db.UserType2NameMap[userType]; !ok {
		err := fmt.Errorf("The User Type does not meet the requirements")
		return err
	}
	return nil
}

func checkParametersCertUsage(certUsage db.CertUsage) error {
	if _, ok := db.CertUsage2NameMap[certUsage]; !ok {
		err := fmt.Errorf("The Cert Usage does not meet the requirements")
		return err
	}
	return nil
}

func getCaType() (utils.CaType, error) {
	var (
		caType utils.CaType
		ok     bool
	)
	if caType, ok = utils.Name2CaTypeMap[AllConfig.GetCaType()]; !ok {
		return caType, fmt.Errorf("[check] ca type is unsupport!Currently supported types: [tls],[sign],[solo] or [double]")
	}
	return caType, nil
}

//通过OrgID寻找签发人，返回签发人的私钥和证书，以及err
func searchIssuedCa(orgID string, certUsage db.CertUsage) (crypto.PrivateKey, []byte, error) {
	//先转换certUsage
	certUsage = covertCertUsage(certUsage)
	//先去找相同OrgID的中间ca
	certInfo, _ := models.FindCertInfoByConditions("", orgID, certUsage, 0)
	if certInfo == nil { //去找rootca签
		certInfo, _ = models.FindCertInfoByConditions("", "", certUsage, db.ROOT_CA)
	}
	certContent, _ := models.FindCertContentBySn(certInfo.IssuerSn)

}

//根据启动模式和用户提供certusage的来确定寻找的CA的certusage字段
//这里已经判断完可以提供了服务了才能使用
func covertCertUsage(certUsage db.CertUsage) db.CertUsage {
	caType, _ := getCaType()
	if caType == utils.DOUBLE {
		return certUsage
	}
	if caType == utils.SOLO || caType == utils.SIGN {
		return db.SIGN
	}
	return db.TLS
}
