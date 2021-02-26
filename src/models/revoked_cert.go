package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//InsertRevokedCert .
func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Debug().Create(revokedCert).Error; err != nil {
		return fmt.Errorf("[DB] create revoked cert info error: %s", err.Error())
	}
	return nil
}

//GetAllRevokedList .
func GetAllRevokedList() ([]db.RevokedCert, error) {
	var revokedCertList []db.RevokedCert
	if err := db.DB.Debug().Find(&revokedCertList).Error; err != nil {
		return nil, fmt.Errorf("[DB] get revoked list error: %s", err.Error())
	}
	return revokedCertList, nil
}
