package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	bcx509 "chainmaker.org/chainmaker-go/common/crypto/x509"
)

//GetCert 从数据库获取证书文件
func GetCert(userID, orgID string, certUsage db.CertUsage, userType db.UserType) ([]db.GetCertResp, error) {
	var getCertResps []db.GetCertResp
	certAndPrivKeys, err := GetCertByConditions(userID, orgID, certUsage, userType)
	if err != nil {
		return nil, err
	}
	getCertResps = make([]db.GetCertResp, len(certAndPrivKeys))
	for i, v := range certAndPrivKeys {
		getCertResps[i].CertContent = v.Cert.Content
		getCertResps[i].PrivateKey = v.KeyPair.PrivateKey
		getCertResps[i].Usage = db.CertUsage2NameMap[v.KeyPair.CertUsage]
	}
	return getCertResps, nil
}

// ParseCertificate - parse certification
func ParseCertificateWithRaw(certRaw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certRaw)
	cert, err := bcx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificate cert failed, %s", err)
	}

	return bcx509.ChainMakerCertToX509Cert(cert)
}
