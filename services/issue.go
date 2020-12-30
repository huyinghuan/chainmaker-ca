package services

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"chainmaker.org/wx-CRA-backend/models/db"
)

//IssueCertificate 签发证书
func IssueCertificate(hashType crypto.HashType, isCA bool, issuerPrivKey crypto.PrivateKey,
	csrBytes, certBytes []byte, expireYear int32, sans []string, uuid string) (*db.Cert, error) {
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
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}

	basicConstraintsValid := false
	if isCA {
		basicConstraintsValid = true
	}

	if expireYear <= 0 {
		expireYear = defaultExpireYear
	}

	dnsName, ipAddrs := dealSANS(sans)

	var extraExtensions []pkix.Extension
	if uuid != "" {
		extSubjectAltName := pkix.Extension{}
		extSubjectAltName.Id = bcx509.OidNodeId
		extSubjectAltName.Critical = false
		extSubjectAltName.Value = []byte(uuid)

		extraExtensions = append(extraExtensions, extSubjectAltName)
	}

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
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		IPAddresses:     ipAddrs,
		DNSNames:        dnsName,
		ExtraExtensions: extraExtensions,
		Subject:         csr.Subject,
	}

	if issuerCert.SubjectKeyId != nil {
		template.AuthorityKeyId = issuerCert.SubjectKeyId
	} else {
		template.AuthorityKeyId, err = cert.ComputeSKI(hashType, issuerCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("issue cert compute issuer cert SKI failed, %s", err.Error())
		}
	}

	template.SubjectKeyId, err = cert.ComputeSKI(hashType, csr.PublicKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue cert compute csr SKI failed, %s", err.Error())
	}

	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, issuerCert,
		csr.PublicKey.ToStandardKey(), issuerPrivKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue certificate failed, %s", err)
	}
	if isCA == true {
		certModel.CaType = "intermediaries"
	} else {
		certModel.CaType = "user"
	}
	certModel.CertEncode = x509certEncode
	certModel.CommonName = csr.Subject.CommonName
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	certModel.Country = template.Subject.Country[0]
	certModel.CsrContent = csrBytes
	certModel.ExpireYear = int32(template.NotAfter.Year()) - int32(template.NotBefore.Year())
	for i, v := range crypto.HashAlgoMap {
		if v == hashType {
			certModel.HashTyep = i
			break
		}
	}
	certModel.Locality = template.Subject.Locality[0]
	certModel.Organization = template.Subject.Organization[0]
	certModel.OrganizationalUnit = template.Subject.OrganizationalUnit[0]
	certModel.Province = template.Subject.Province[0]
	certModel.SerialNumber = template.SerialNumber.Int64()
	certModel.Signature = template.Signature
	return &certModel, nil
}

//CreateCSR 创建CSR
func CreateCSR(privKey crypto.PrivateKey, country, locality, province,
	organizationalUnit, organization, commonName string) ([]byte, error) {
	templateX509 := cert.GenerateCSRTemplate(privKey, country, locality, province, organizationalUnit, organization, commonName)

	template, err := bcx509.X509CertCsrToChainMakerCertCsr(templateX509)
	if err != nil {
		return nil, fmt.Errorf("generate csr failed, %s", err.Error())
	}

	data, err := bcx509.CreateCertificateRequest(rand.Reader, template, privKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("CreateCertificateRequest failed, %s", err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}), nil
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
