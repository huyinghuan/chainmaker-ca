package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Debug().Create(revokedCert).Error; err != nil {
		return fmt.Errorf("[DB] create revoked cert info failed: %s", err.Error())
	}
	return nil
}
