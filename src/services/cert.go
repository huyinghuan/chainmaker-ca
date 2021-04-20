package services

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/crypto"
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

func ImportOrgCa(privKey crypto.PrivateKey, Id string, cert *x509.Certificate, keyPairUser db.KeyPairUser, hashType crypto.HashType, certBytes []byte) error {
	if dbCert, err := models.GetCertBySN(cert.SerialNumber.Int64()); err == nil && dbCert != nil {
		return nil
	}

	var certModel db.Cert
	certModel.IsCa = true
	certModel.CertEncode = hex.EncodeToString(certBytes)
	certModel.CommonName = cert.Subject.CommonName
	certModel.Content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certModel.Country = cert.Subject.Country[0]
	certModel.ExpireYear = int32((cert.NotAfter.Unix() - cert.NotBefore.Unix()) / int64(365*24*time.Hour))
	certModel.HashType = hashType
	certModel.IssueDate = cert.NotBefore.Unix()
	certModel.InvalidDate = cert.NotAfter.Unix()
	certModel.Locality = cert.Subject.Locality[0]
	certModel.Organization = cert.Subject.Organization[0]
	certModel.OrganizationalUnit = cert.Subject.OrganizationalUnit[0]
	certModel.Province = cert.Subject.Province[0]

	csrBytes, err := createCSR(privKey, certModel.Country, certModel.Locality, certModel.Province, certModel.OrganizationalUnit, certModel.Organization, certModel.CommonName)
	if nil != err {
		return err
	}
	csrOriginal, err := ParseCsr(csrBytes)
	if err != nil {
		return err
	}
	csr, err := bcx509.X509CertCsrToChainMakerCertCsr(csrOriginal)
	if err != nil {
		return fmt.Errorf("[Issue cert] X509 cert to chainmaker error: %s", err.Error())
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("[Issue cert] csr check signature error: %s", err.Error())
	}

	certModel.SerialNumber = cert.SerialNumber.Int64()
	certModel.CsrContent = csrBytes
	certModel.Signature = hex.EncodeToString(csr.Signature)
	certModel.CertSans = "[]"
	certModel.CertStatus = db.EFFECTIVE
	certModel.PrivateKeyID = Id
	//证书入库
	err = models.InsertCert(&certModel)
	if err != nil {
		return err
	}
	return nil
}
