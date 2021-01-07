package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertRevokedCert .
func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Debug().Create(revokedCert).Error; err != nil {
		return err
	}
	return nil
}
