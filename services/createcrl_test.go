package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto/asym"
	"chainmaker.org/chainmaker-go/common/crypto/x509"
)

func TestCreateCRL(t *testing.T) {
	//读取本地要撤销的证书 主要拿到证书的sn字段
	revokedCertPath := "../testcrl/cert.crt"
	issuerCertPath := "../testcrl/ca.crt"
	issuerPrivKeyPath := "../testcrl/ca.key"
	testcrlPath := "../testcrl/test.crl"
	revokedCert, err := cert.ParseCertificate(revokedCertPath)
	if err != nil {
		fmt.Printf("revoked cert: %s", err.Error())
		return
	}

	issuerPrivKeyRaw, err := ioutil.ReadFile(issuerPrivKeyPath)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}
	issuerCert, err := cert.ParseCertificate(issuerCertPath)
	if err != nil {
		fmt.Printf("revoked cert: %s", err.Error())
		return
	}
	block, _ := pem.Decode(issuerPrivKeyRaw)
	issuerPrivKey, err := asym.PrivateKeyFromDER(block.Bytes)
	if err != nil {
		fmt.Printf("private key from der: %s", err.Error())
	}
	var revokedCerts []pkix.RevokedCertificate
	var revoked pkix.RevokedCertificate
	certSn := revokedCert.SerialNumber
	revoked.SerialNumber = big.NewInt(certSn.Int64())
	revoked.RevocationTime = time.Unix(1711206185, 0)
	revokedCerts = append(revokedCerts, revoked)
	now := time.Now()
	next := now.Add(time.Duration(4) * time.Hour) //撤销列表过期时间（4小时候这个撤销列表就不是最新的了）
	crlBytes, err := x509.CreateCRL(rand.Reader, issuerCert, issuerPrivKey.ToStandardKey(), revokedCerts, now, next)
	err = ioutil.WriteFile(testcrlPath, pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlBytes}), os.ModePerm)
	if err != nil {
		fmt.Println(err.Error())
	}
}
