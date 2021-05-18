package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"gorm.io/gorm"
)

func InsertCertContent(certContent *db.CertContent) error {
	if err := db.DB.Debug().Create(certContent).Error; err != nil {
		return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
	}
	return nil
}

func MulInsertCertContents(certContents []*db.CertContent) error {
	len := len(certContents)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(certContents, len).Error; err != nil {
			return fmt.Errorf("[DB] create multiple cert contents to db failed: %s", err.Error())
		}
		return nil
	})
	return err
}

func FindCertContentBySn(sn int64) (*db.CertContent, error) {
	var certContent db.CertContent
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certContent).Error; err != nil {
		return nil, fmt.Errorf("[DB] find cert content by sn error: %s, sn: %d", err.Error(), sn)
	}
	return &certContent, nil
}

func IsCertContentExist(sn int64) *db.CertContent {
	var certContent db.CertContent
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certContent).Error; err != nil {
		return nil
	}
	return &certContent
}
