package models

import (
	"chainmaker.org/wx-CRA-backend/models/db"
)

//InsertCert 插入证书
func InsertCert(cert *db.Cert) error {
	if err := db.DB.Debug().Create(cert).Error; err != nil {
		return err
	}
	return nil
}

//GetCertByID .
func GetCertByID(certID int) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("id=?", certID).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}
