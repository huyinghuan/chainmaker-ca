package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func InsertCertContent(certContent *db.CertContent) error {
	if err := db.DB.Debug().Create(certContent).Error; err != nil {
		return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
	}
	return nil
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
