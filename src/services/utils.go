package services

import (
	"archive/zip"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
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
func KeyBytesToPrivateKey(privateKeyBytes []byte, hexHashPwd string, hashType crypto.HashType) (privateKey crypto.PrivateKey, err error) {
	if len(hexHashPwd) == 0 {
		privateKey, err = ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return
		}
	}
	privateKey, err = decryptPrivKey(privateKeyBytes, hexHashPwd, hashType)
	if err != nil {
		return
	}
	return
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
	return allConfig.GetCanIssueCa()
}

func provideServiceFor() []string {
	return allConfig.GetProvideServiceFor()
}
func hashTypeFromConfig() string {
	return allConfig.GetHashType()
}
func expireYearFromConfig() int {
	return allConfig.GetDefaultExpireTime()
}

func checkIntermediateCaConf() []*utils.CaConfig {
	if len(allConfig.GetIntermediateConf()) == 0 {
		return nil
	}
	return allConfig.GetIntermediateConf()
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
		err := fmt.Errorf("the User Type does not meet the requirements")
		return err
	}
	return nil
}

func checkParametersCertUsage(certUsage db.CertUsage) error {
	if _, ok := db.CertUsage2NameMap[certUsage]; !ok {
		err := fmt.Errorf("the Cert Usage does not meet the requirements")
		return err
	}
	return nil
}

func getCaType() (utils.CaType, error) {
	var (
		caType utils.CaType
		ok     bool
	)
	if caType, ok = utils.Name2CaTypeMap[allConfig.GetCaType()]; !ok {
		return caType, fmt.Errorf("[check] ca type is unsupport!Currently supported types: [tls],[sign],[solo] or [double]")
	}
	return caType, nil
}

//通过OrgID寻找签发人，返回签发人的私钥和证书，以及err
func searchIssuedCa(orgID string, certUsage db.CertUsage) (crypto.PrivateKey, []byte, error) {
	//先转换certUsage
	certUsage = covertCertUsage(certUsage)
	//先去找相同OrgID的中间ca
	certInfo, err := models.FindActiveCertInfoByConditions("", orgID, certUsage, 0)
	if err != nil || certInfo.UserType != db.INTERMRDIARY_CA { //去找rootca签
		certInfo, err = models.FindActiveCertInfoByConditions("", "", certUsage, db.ROOT_CA)
		if err != nil {
			return nil, nil, err
		}
	}
	certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
	if err != nil {
		return nil, nil, err
	}
	keyPair, err := models.FindKeyPairBySki(certInfo.PrivateKeyId)
	if err != nil {
		return nil, nil, err
	}
	reCertContent, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, nil, err
	}
	//需要一个能加密的类型密钥，不要字符串,需要再想办法转换
	dePrivatKey, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := KeyBytesToPrivateKey(dePrivatKey, keyPair.PrivateKeyPwd, keyPair.HashType)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, reCertContent, nil
}

//根据启动模式和用户提供certusage的来确定寻找的CA的certusage字段
//这里已经判断完可以提供了服务了才能使用
func covertCertUsage(certUsage db.CertUsage) db.CertUsage {
	caType, _ := getCaType()
	if caType == utils.DOUBLE_ROOT {
		if certUsage == db.SIGN {
			return db.SIGN
		} else {
			return db.TLS
		}
	}
	if caType == utils.SINGLE_ROOT || caType == utils.SIGN {
		return db.SIGN
	}
	return db.TLS
}

func ReadWithFile(file multipart.File) ([]byte, error) {
	var result []byte
	var tmp = make([]byte, 128)
	for {
		n, err := file.Read(tmp)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		result = append(result, tmp[:n]...)
	}
	return result, nil
}

func ZipCertAndPrivateKey(certContent []byte, privateKey []byte) ([]byte, error) {
	fileName := "cert&privateKey.zip"
	file, err := os.Create(utils.DefaultWorkDirectory + fileName)
	if err != nil {
		return nil, err
	}
	writer := zip.NewWriter(file)
	f, err := writer.Create("cert.crt")
	if err != nil {
		return nil, err
	}
	f.Write(certContent)
	if privateKey != nil {
		f, err = writer.Create("privateKey.key")
		if err != nil {
			return nil, err
		}
		f.Write(privateKey)
	}
	writer.Close()
	content, err := ioutil.ReadFile(utils.DefaultWorkDirectory + fileName)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(utils.DefaultWorkDirectory + fileName)
	defer file.Close()
	return content, nil
}

func GetX509Certificate(Sn int64) (*x509.Certificate, error) {
	certContent, err := models.FindCertContentBySn(Sn)
	if err != nil {
		return nil, err
	}
	certContentByte, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, err
	}
	certContentByteUse, err := ParseCertificate(certContentByte)
	if err != nil {
		return nil, err
	}
	return certContentByteUse, nil
}
