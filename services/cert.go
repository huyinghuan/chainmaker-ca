package services

import (
	"chainmaker.org/wx-CRA-backend/models/db"
	"go.uber.org/zap"
)

//GetCert 从数据库获取证书文件
func GetCert(userID, orgID, chainID string, certUsage db.CertUsage, userType db.UserType) ([]db.GetCertResp, error) {
	var getCertResps []db.GetCertResp
	if userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS {
		userID = chainID + "-" + userID
	}
	certAndPrivKeys, err := GetCertByConditions(userID, orgID, certUsage, userType)
	if err != nil {
		logger.Error("Get cert by conditions failed!", zap.Error(err))
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
