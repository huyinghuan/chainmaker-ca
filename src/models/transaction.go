/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"gorm.io/gorm"
)

//The  transaction that inserts cert, kepair, and certinfo into the database
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

//The  transaction that inserts cert and certinfo into the database
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

//The  transaction that updata old cert and inserts new cert and new certinfo into the database
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
