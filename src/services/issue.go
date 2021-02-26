package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
)

//IssueCertificate 签发证书
func IssueCertificate(hashType crypto.HashType, isCA bool, keyID string, issuerPrivKey crypto.PrivateKey,
	csrBytes, certBytes []byte, expireYear int32, sans []string) (*db.Cert, error) {
	//判断库里证书是否存在
	dbCert, certIsExist := models.CertIsExist(keyID)
	if certIsExist {
		return dbCert, nil
	}
	var certModel db.Cert
	issuerCert, err := ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	csrOriginal, err := ParseCsr(csrBytes)
	if err != nil {
		return nil, err
	}
	csr, err := bcx509.X509CertCsrToChainMakerCertCsr(csrOriginal)
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] X509 cert to chainmaker error: %s", err.Error())
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("[Issue cert] csr check signature error: %s", err.Error())
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] rand int error: %s", err.Error())
	}

	basicConstraintsValid := false
	if isCA == true {
		basicConstraintsValid = true
	}

	if expireYear <= 0 {
		expireYear = defaultExpireYear
	}

	dnsName, ipAddrs := dealSANS(sans)

	notBefore := time.Now().Add(-10 * time.Minute).UTC()
	template := &x509.Certificate{
		Signature:             csr.Signature,
		SignatureAlgorithm:    x509.SignatureAlgorithm(csr.SignatureAlgorithm),
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    x509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm),
		SerialNumber:          sn,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(expireYear) * 365 * 24 * time.Hour).UTC(),
		BasicConstraintsValid: basicConstraintsValid,
		IsCA:                  isCA,
		Issuer:                issuerCert.Subject,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		IPAddresses: ipAddrs,
		DNSNames:    dnsName,
		Subject:     csr.Subject,
	}

	if issuerCert.SubjectKeyId != nil {
		template.AuthorityKeyId = issuerCert.SubjectKeyId
	} else {
		template.AuthorityKeyId, err = cert.ComputeSKI(hashType, issuerCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("[Issue cert] issue cert compute issuer cert SKI failed: %s", err.Error())
		}
	}

	template.SubjectKeyId, err = cert.ComputeSKI(hashType, csr.PublicKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] issue cert compute csr SKI failed, %s", err.Error())
	}

	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, issuerCert,
		csr.PublicKey.ToStandardKey(), issuerPrivKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] issue certificate failed, %s", err)
	}
	certModel.IsCa = isCA
	certModel.CertEncode = hex.EncodeToString(x509certEncode)
	certModel.CommonName = csr.Subject.CommonName
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	certModel.Country = template.Subject.Country[0]
	certModel.CsrContent = csrBytes
	certModel.ExpireYear = expireYear
	certModel.HashType = hashType
	certModel.IssueDate = template.NotBefore.Unix()
	certModel.InvalidDate = template.NotAfter.Unix()
	certModel.Locality = template.Subject.Locality[0]
	certModel.Organization = template.Subject.Organization[0]
	certModel.OrganizationalUnit = template.Subject.OrganizationalUnit[0]
	certModel.Province = template.Subject.Province[0]
	certModel.SerialNumber = template.SerialNumber.Int64()
	certModel.Signature = hex.EncodeToString(template.Signature)
	sansstr, err := json.Marshal(sans)
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] marshal sans failed: %s", err.Error())
	}
	certModel.CertSans = string(sansstr)
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = keyID
	//证书入库
	err = models.InsertCert(&certModel)
	if err != nil {
		return nil, err
	}
	return &certModel, nil
}

//CreateCSR 创建CSR
func createCSR(privKey crypto.PrivateKey, country, locality, province,
	organizationalUnit, organization, commonName string) ([]byte, error) {
	templateX509 := cert.GenerateCSRTemplate(privKey, country, locality, province, organizationalUnit, organization, commonName)

	template, err := bcx509.X509CertCsrToChainMakerCertCsr(templateX509)
	if err != nil {
		return nil, fmt.Errorf("[Create csr] generate csr failed, %s", err.Error())
	}

	data, err := bcx509.CreateCertificateRequest(rand.Reader, template, privKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create csr] createCertificateRequest failed, %s", err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data}), nil
}
