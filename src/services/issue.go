package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/cert"
	"chainmaker.org/chainmaker-go/common/crypto"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
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

type GenCertRequestConfig struct {
	Country            []string
	Locality           []string
	Province           []string
	OrganizationalUnit []string
	Organization       []string
	CommonName         string
	ExpireYear         int32
	CertUsage          db.CertUsage
	UserType           db.UserType
}

type RootCertRequestConfig struct {
	PrivateKey         crypto.PrivateKey
	Country            string
	Locality           string
	Province           string
	OrganizationalUnit string
	Organization       string
	CommonName         string
	ExpireYear         int32
	CertUsage          db.CertUsage
	UserType           db.UserType
	HashType           string
}

func IssueCertBySelf(rootCertConf *RootCertRequestConfig) (*db.CertContent, error) {
	genCertConf := &GenCertRequestConfig{
		Country:            []string{rootCertConf.Country},
		Locality:           []string{rootCertConf.Locality},
		Province:           []string{rootCertConf.Province},
		OrganizationalUnit: []string{rootCertConf.OrganizationalUnit},
		Organization:       []string{rootCertConf.Organization},
		CommonName:         rootCertConf.CommonName,
		ExpireYear:         rootCertConf.ExpireYear,
		CertUsage:          rootCertConf.CertUsage,
		UserType:           rootCertConf.UserType,
	}
	template, err := generateCertTemplate(genCertConf)
	if err != nil {
		return nil, err
	}
	template.SignatureAlgorithm = getSignatureAlgorithm(rootCertConf.PrivateKey)
	hashType, err := checkHashType(rootCertConf.HashType)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId, err = cert.ComputeSKI(hashType, rootCertConf.PrivateKey.PublicKey().ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create ca cert] create CA cert compute SKI failed, %s", err.Error())
	}
	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, template,
		rootCertConf.PrivateKey.PublicKey().ToStandardKey(), rootCertConf.PrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("[Create ca cert] create CA cert failed, %s", err.Error())
	}
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	extKeyUsageStr, err := ExtKeyUsageToString(template.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:       template.SerialNumber.Int64(),
		Content:            base64.StdEncoding.EncodeToString(certPemBytes),
		Signature:          hex.EncodeToString(template.Signature),
		CertRaw:            base64.StdEncoding.EncodeToString(x509certEncode),
		Country:            template.Subject.Country[0],
		Locality:           template.Subject.Locality[0],
		Province:           template.Subject.Province[0],
		Organization:       template.Subject.Organization[0],
		OrganizationalUnit: template.Subject.OrganizationalUnit[0],
		CommonName:         template.Subject.CommonName,
		Ski:                hex.EncodeToString(template.SubjectKeyId),
		Aki:                hex.EncodeToString(template.AuthorityKeyId),
		KeyUsage:           int(template.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		IsCa:               template.IsCA,
		IssueDate:          template.NotBefore.Unix(),
		InvalidDate:        template.NotAfter.Unix(),
	}
	return certContent, nil
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
		return nil, fmt.Errorf("[issue cert] X509 cert to chainmaker error: %s", err.Error())
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("[issue cert] csr check signature error: %s", err.Error())
	}
	genConf := &GenCertRequestConfig{
		Country:            csr.Subject.Country,
		Locality:           csr.Subject.Locality,
		Province:           csr.Subject.Province,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Organization:       csr.Subject.Organization,
		CommonName:         csr.Subject.CommonName,
		CertUsage:          certConf.CertUsage,
		UserType:           certConf.UserType,
		ExpireYear:         certConf.ExpireYear,
	}
	template, err := generateCertTemplate(genConf)
	if err != nil {
		return nil, err
	}
	template.Signature = csr.Signature
	template.SignatureAlgorithm = x509.SignatureAlgorithm(csr.SignatureAlgorithm)
	template.PublicKey = csr.PublicKey
	template.PublicKeyAlgorithm = x509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm)
	template.Issuer = issuerCert.Subject
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
	extKeyUsageStr, err := ExtKeyUsageToString(template.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:       template.SerialNumber.Int64(),
		Content:            base64.StdEncoding.EncodeToString(certPemBytes),
		Signature:          hex.EncodeToString(template.Signature),
		CertRaw:            base64.StdEncoding.EncodeToString(x509certEncode),
		Country:            template.Subject.Country[0],
		Locality:           template.Subject.Locality[0],
		Province:           template.Subject.Province[0],
		Organization:       template.Subject.Organization[0],
		OrganizationalUnit: template.Subject.OrganizationalUnit[0],
		CommonName:         template.Subject.CommonName,
		Ski:                hex.EncodeToString(template.SubjectKeyId),
		Aki:                hex.EncodeToString(template.AuthorityKeyId),
		KeyUsage:           int(template.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		CsrContent:         base64.StdEncoding.EncodeToString(certConf.CsrBytes),
		IsCa:               template.IsCA,
		IssueDate:          template.NotBefore.Unix(),
		InvalidDate:        template.NotAfter.Unix(),
	}
	return certContent, nil
}

//createCSR create csr
func createCSR(csrConf *CSRRequestConfig) ([]byte, error) {

	signatureAlgorithm := getSignatureAlgorithm(csrConf.PrivateKey)

	templateX509 := &x509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
		Subject: pkix.Name{
			Country:            []string{csrConf.Country},
			Locality:           []string{csrConf.Locality},
			Province:           []string{csrConf.Province},
			OrganizationalUnit: []string{csrConf.OrganizationalUnit},
			Organization:       []string{csrConf.Organization},
			CommonName:         csrConf.CommonName,
		},
	}
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

func getKeyUsageAndExtKeyUsage(userType db.UserType, certUsage db.CertUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var (
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
		err         error
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
		case db.TLS:
			err = fmt.Errorf("the cert usage does not match the user type")
			return keyUsage, extKeyUsage, err
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
	return keyUsage, extKeyUsage, nil
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

func generateCertTemplate(genConf *GenCertRequestConfig) (*x509.Certificate, error) {
	sn, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, fmt.Errorf("[issue cert] rand int error: %s", err.Error())
	}
	basicConstraintsValid := false
	isCA := false
	if genConf.UserType == db.INTERMRDIARY_CA || genConf.UserType == db.ROOT_CA {
		basicConstraintsValid = true
		isCA = true
	}

	if genConf.ExpireYear <= 0 {
		genConf.ExpireYear = int32(allConfig.GetDefaultExpireTime())
	}
	var dnsName string
	if genConf.UserType == db.NODE_COMMON || genConf.UserType == db.NODE_CONSENSUS {
		dnsName = genConf.CommonName
	}

	keyUsage, extKeyUsage, err := getKeyUsageAndExtKeyUsage(genConf.UserType, genConf.CertUsage)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-10 * time.Minute).UTC()

	template := &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(genConf.ExpireYear) * 365 * 24 * time.Hour).UTC(),
		BasicConstraintsValid: basicConstraintsValid,
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              []string{dnsName},
		Subject: pkix.Name{
			Country:            genConf.Country,
			Locality:           genConf.Locality,
			Province:           genConf.Province,
			OrganizationalUnit: genConf.OrganizationalUnit,
			Organization:       genConf.Organization,
			CommonName:         genConf.CommonName,
		},
	}
	return template, nil
}

func getSignatureAlgorithm(privKey crypto.PrivateKey) x509.SignatureAlgorithm {
	signatureAlgorithm := x509.ECDSAWithSHA256
	switch privKey.PublicKey().ToStandardKey().(type) {
	case *rsa.PublicKey:
		signatureAlgorithm = x509.SHA256WithRSA
	case *sm2.PublicKey:
		signatureAlgorithm = x509.SignatureAlgorithm(bcx509.SM3WithSM2)
	}

	return signatureAlgorithm
}

func TransfToCertContent(certBytes []byte) (cert *x509.Certificate, certContent *db.CertContent, err error) {
	cert, err = ParseCertificate(certBytes)
	if err != nil {
		return
	}
	var extKeyUsageStr string
	extKeyUsageStr, err = ExtKeyUsageToString(cert.ExtKeyUsage)
	if err != nil {
		return
	}
	certContent = &db.CertContent{
		SerialNumber:       cert.SerialNumber.Int64(),
		Content:            base64.StdEncoding.EncodeToString(certBytes),
		Signature:          hex.EncodeToString(cert.Signature),
		CertRaw:            base64.StdEncoding.EncodeToString(cert.Raw),
		Country:            cert.Subject.Country[0],
		Locality:           cert.Subject.Locality[0],
		Province:           cert.Subject.Province[0],
		Organization:       cert.Subject.Organization[0],
		OrganizationalUnit: cert.Subject.OrganizationalUnit[0],
		CommonName:         cert.Subject.CommonName,
		Ski:                hex.EncodeToString(cert.SubjectKeyId),
		Aki:                hex.EncodeToString(cert.AuthorityKeyId),
		KeyUsage:           int(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		IsCa:               cert.IsCA,
		IssueDate:          cert.NotBefore.Unix(),
		InvalidDate:        cert.NotAfter.Unix(),
	}
	return
}
