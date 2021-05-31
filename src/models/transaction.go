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

func CreateCertAndInfoTransaction(certContent *db.CertContent, certInfo *db.CertInfo) error {
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

func CreateCertAndUpdateTransaction(certContent *db.CertContent, oldCertInfo *db.CertInfo, newCertInfo *db.CertInfo) error {
	err := db.DB.Debug().Transaction(func(tx *gorm.DB) error {
		if err := db.DB.Debug().Model(&db.CertInfo{}).
			Where("serial_number=?", oldCertInfo.SerialNumber).Update("cert_status", db.EXPIRED).Error; err != nil {
			err = fmt.Errorf("[DB] find cert info by sn failed: %s", err.Error())
			return err
		}
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := tx.Create(newCertInfo).Error; err != nil {
			return fmt.Errorf("[DB] create certInfo to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		return nil
	})
	return err
}
