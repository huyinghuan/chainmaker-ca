package services

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"

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
