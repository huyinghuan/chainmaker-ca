package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertRevokedCert .
func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Debug().Create(revokedCert).Error; err != nil {
		return err
	}
	return nil
}

//GetAllRevokedList .
func GetAllRevokedList() ([]db.RevokedCert, error) {
	var revokedCertList []db.RevokedCert
	if err := db.DB.Debug().Find(&revokedCertList).Error; err != nil {
		return nil, err
	}
	return revokedCertList, nil
}
