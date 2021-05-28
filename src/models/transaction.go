package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"gorm.io/gorm"
)

func CreateCertTransaction(certContent *db.CertContent, certInfo *db.CertInfo, keyPair *db.KeyPair) error {
	err := db.DB.Debug().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(keyPair).Error; err != nil {
			return fmt.Errorf("[DB] create key pair error: %s", err.Error())
		}
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := tx.Create(certInfo).Error; err != nil {
			return fmt.Errorf("[DB] create cert info to db failed: %s, sn: %d", err.Error(), certInfo.SerialNumber)
		}
		return nil
	})
	return err
}
func CreateCertTwoTransaction(certContent *db.CertContent, certInfo *db.CertInfo) error {
	err := db.DB.Debug().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := tx.Create(certInfo).Error; err != nil {
			return fmt.Errorf("[DB] create cert info to db failed: %s, sn: %d", err.Error(), certInfo.SerialNumber)
		}
		return nil
	})
	return err
}
func CreateCertAndUpdateTransaction(certContent *db.CertContent, certInfo *db.CertInfo) error {
	err := db.DB.Debug().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := db.DB.Debug().Model(&db.CertInfo{}).
			Where("serial_number=?", certInfo.SerialNumber).Update("serial_number", certContent.SerialNumber).Error; err != nil {
			err = fmt.Errorf("[DB] find cert info by sn failed: %s", err.Error())
			return err
		}
		return nil
	})
	return err
}
