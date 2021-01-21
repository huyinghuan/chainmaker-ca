package services

import (
	"fmt"

	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"go.uber.org/zap"
)

//GetCert 从数据库获取证书文件
func GetCert(userID, orgID, chainID string, certUsage db.CertUsage, userType db.UserType) ([]byte, error) {
	keyPair, err := models.GetKeyPairByConditions(userID, orgID, chainID, certUsage, userType)
	if err == db.GormErrRNF {
		logger.Error("Cert is not exist")
		return nil, fmt.Errorf("Cert is not exist")
	}
	if err != nil {
		logger.Error("Get key pair by conditions failed!", zap.Error(err))
		return nil, err
	}
	cert, err := models.GetCertByPrivateKeyID(keyPair.ID)
	if err != nil {
		logger.Error("Get cert by private key failed!", zap.Error(err))
		return nil, err
	}
	return cert.Content, nil
}
