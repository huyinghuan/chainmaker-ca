package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
)

type CSRRequestConfig struct {
	PrivateKey         crypto.PrivateKey
	Country            string
	Locality           string
	Province           string
	OrganizationalUnit string
	Organization       string
	CommonName         string
}

type CertRequestConfig struct {
	HashType         crypto.HashType
	IssuerPrivateKey crypto.PrivateKey
	CsrBytes         []byte
	IssuerCertBytes  []byte
	ExpireYear       int32
	CertUsage        db.CertUsage
	UserType         db.UserType
}

func IssueCertificate(certConf *CertRequestConfig) (*db.CertContent, error) {
	issuerCert, err := ParseCertificate(certConf.IssuerCertBytes)
	if err != nil {
		return nil, err
	}
	csrOriginal, err := ParseCsr(certConf.CsrBytes)
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
	isCA := false
	if certConf.UserType == db.INTERMRDIARY_CA || certConf.UserType == db.ROOT_CA {
		basicConstraintsValid = true
		isCA = true
	}

	if certConf.ExpireYear <= 0 {
		certConf.ExpireYear = utils.GetDefaultExpireTime()
	}
	var dnsName string
	if certConf.UserType == db.NODE_COMMON || certConf.UserType == db.NODE_CONSENSUS {
		dnsName = csr.Subject.CommonName
	}

	keyUsage, extKeyUsage := getKeyUsageAndExtKeyUsage(certConf.UserType, certConf.CertUsage)
	notBefore := time.Now().Add(-10 * time.Minute).UTC()
	template := &x509.Certificate{
		Signature:             csr.Signature,
		SignatureAlgorithm:    x509.SignatureAlgorithm(csr.SignatureAlgorithm),
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    x509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm),
		SerialNumber:          sn,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(certConf.ExpireYear) * 365 * 24 * time.Hour).UTC(),
		BasicConstraintsValid: basicConstraintsValid,
		IsCA:                  isCA,
		Issuer:                issuerCert.Subject,
		DNSNames:              []string{dnsName},
		Subject:               csr.Subject,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
	}

	if issuerCert.SubjectKeyId != nil {
		template.AuthorityKeyId = issuerCert.SubjectKeyId
	} else {
		template.AuthorityKeyId, err = cert.ComputeSKI(certConf.HashType, issuerCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("[Issue cert] issue cert compute issuer cert SKI failed: %s", err.Error())
		}
	}

	template.SubjectKeyId, err = cert.ComputeSKI(certConf.HashType, csr.PublicKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] issue cert compute csr SKI failed, %s", err.Error())
	}

	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, issuerCert,
		csr.PublicKey.ToStandardKey(), certConf.IssuerPrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Issue cert] issue certificate failed, %s", err)
	}
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	extKeyUsageStr, err := ExtKeyUsageToString(extKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:       template.SerialNumber.Int64(),
		Content:            base64.StdEncoding.EncodeToString(certPemBytes),
		Signature:          hex.EncodeToString(template.Signature),
		CertRow:            base64.StdEncoding.EncodeToString(x509certEncode),
		Country:            template.Subject.Country[0],
		Locality:           template.Subject.Locality[0],
		Province:           template.Subject.Province[0],
		Organization:       template.Subject.Organization[0],
		OrganizationalUnit: template.Subject.OrganizationalUnit[0],
		CommonName:         template.Subject.CommonName,
		Ski:                hex.EncodeToString(template.SubjectKeyId),
		Aki:                hex.EncodeToString(template.AuthorityKeyId),
		KeyUsage:           int(keyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		CsrContent:         base64.StdEncoding.EncodeToString(certConf.CsrBytes),
		IsCa:               isCA,
		IssueDate:          template.NotBefore.Unix(),
		InvalidDate:        template.NotAfter.Unix(),
	}
	err = models.InsertCertContent(certContent)
	if err != nil {
		return nil, err
	}
	return certContent, nil
}

//createCSR create csr
func createCSR(csrConf *CSRRequestConfig) ([]byte, error) {
	templateX509 := cert.GenerateCSRTemplate(csrConf.PrivateKey, csrConf.Country, csrConf.Locality, csrConf.Province,
		csrConf.OrganizationalUnit, csrConf.Organization, csrConf.CommonName)

	template, err := bcx509.X509CertCsrToChainMakerCertCsr(templateX509)
	if err != nil {
		return nil, fmt.Errorf("[Create csr] generate csr failed, %s", err.Error())
	}

	data, err := bcx509.CreateCertificateRequest(rand.Reader, template, csrConf.PrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create csr] createCertificateRequest failed, %s", err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data}), nil
}

func getKeyUsageAndExtKeyUsage(userType db.UserType, certUsage db.CertUsage) (x509.KeyUsage, []x509.ExtKeyUsage) {
	var (
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
	)
	if userType == db.INTERMRDIARY_CA || userType == db.ROOT_CA {
		keyUsage = x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	}
	if userType == db.USER_ADMIN || userType == db.USER_CLIENT ||
		userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS {
		switch certUsage {
		case db.TLS_ENC:
			keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement
		case db.TLS_SIGN:
			keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		case db.SIGN:
			keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		}
	}
	if userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS {
		if certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN {
			extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}
	}
	if userType == db.USER_ADMIN || userType == db.USER_CLIENT {
		if certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN {
			extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	return keyUsage, extKeyUsage
}

type CSRRequest struct {
	OrgId      string
	UserId     string
	UserType   db.UserType
	Country    string
	Locality   string
	Province   string
	PrivateKey crypto.PrivateKey
}

func BuildCSRReqConf(csrReq *CSRRequest) *CSRRequestConfig {
	OU := db.UserType2NameMap[csrReq.UserType]
	O := csrReq.OrgId
	var CN string
	if csrReq.UserType == db.INTERMRDIARY_CA || csrReq.UserType == db.ROOT_CA {
		CN = db.UserType2NameMap[csrReq.UserType] + "." + csrReq.OrgId
	}
	if csrReq.UserType == db.USER_ADMIN || csrReq.UserType == db.USER_CLIENT {
		CN = csrReq.UserId + "." + csrReq.OrgId
	}
	if csrReq.UserType == db.NODE_COMMON || csrReq.UserType == db.NODE_CONSENSUS {
		//node dns name
		CN = csrReq.UserId
	}
	return &CSRRequestConfig{
		PrivateKey:         csrReq.PrivateKey,
		Country:            csrReq.Country,
		Locality:           csrReq.Locality,
		Province:           csrReq.Province,
		OrganizationalUnit: OU,
		Organization:       O,
		CommonName:         CN,
	}
}
