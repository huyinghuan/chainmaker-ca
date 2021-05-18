package models

import "chainmaker.org/chainmaker-ca-backend/src/models/db"

func FindCertContentByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.CertContent, error) {
	certInfo, err := FindCertInfoByConditions(userId, orgId, usage, userType)
	if err != nil {
		return nil, err
	}
	certSn := certInfo.SerialNumber
	certContent, err := FindCertContentBySn(certSn)
	if err != nil {
		return nil, err
	}
	return certContent, nil
}

func FindKeyPairByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.KeyPair, error) {
	certInfo, err := FindCertInfoByConditions(userId, orgId, usage, userType)
	if err != nil {
		return nil, err
	}
	keyPairSki := certInfo.PrivateKeyId
	keyPair, err := FindKeyPairBySki(keyPairSki)
	if err != nil {
		return nil, err
	}
	return keyPair, nil
}
