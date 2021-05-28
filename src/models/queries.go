package models

import "chainmaker.org/chainmaker-ca-backend/src/models/db"

func FindActiveCertContentByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.CertContent, error) {
	certInfo, err := FindActiveCertInfoByConditions(userId, orgId, usage, userType)
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

func FindActiveKeyPairByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.KeyPair, error) {
	certInfo, err := FindActiveCertInfoByConditions(userId, orgId, usage, userType)
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

func FindCertContentByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType, certStatus db.CertStatus) ([]*db.CertContent, error) {
	certInfoList, err := FindCertInfoByConditions(userId, orgId, usage, userType, certStatus)
	if err != nil {
		return nil, err
	}
	var res []*db.CertContent
	for _, value := range certInfoList {
		tmp, err := FindCertContentBySn(value.SerialNumber)
		if err != nil {
			return nil, err
		}
		res = append(res, tmp)
	}
	return res, nil
}
