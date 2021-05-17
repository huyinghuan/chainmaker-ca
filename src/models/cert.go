package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//InsertCert Insert certificate to db
func InsertCert(cert *db.Cert) error {
	if err := db.DB.Debug().Create(cert).Error; err != nil {
		return fmt.Errorf("[DB] create cert error: %s", err.Error())
	}
	return nil
}

//GetCertBySN
func GetCertBySN(certSN int64) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("serial_number=?", certSN).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return &cert, nil
}

//UpdateCertStatusRevokedBySN
func UpdateCertStatusRevokedBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=?", certSN).Update("cert_status", db.REVOKED).Error; err != nil {
		return fmt.Errorf("[DB] update cert status revoked by sn error: %s", err.Error())
	}
	return nil
}

//UpdateCertStatusExpiredBySN
func UpdateCertStatusExpiredBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=?", certSN).Update("cert_status", db.EXPIRED).Error; err != nil {
		return fmt.Errorf("[DB] update cert status expired by sn error: %s", err.Error())
	}
	return nil
}

//GetCertByPrivateKeyID .
func GetCertByPrivateKeyID(privateKeyID string) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=? AND cert_status=?", privateKeyID, db.ACTIVE).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by private key id error: %s, %s", err.Error(), privateKeyID)
	}
	return &cert, nil
}

//GetCertByPrivateKeyIDWithOutStatus.
func GetCertByPrivateKeyIDWithOutStatus(privateKeyID string) ([]db.Cert, error) {
	var certs []db.Cert
	if err := db.DB.Debug().Table("cert").Where("private_key_id=?", privateKeyID).Scan(&certs).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by private key id error: %s, %s", err.Error(), privateKeyID)
	}
	return certs, nil
}

//IsCertExist
func IsCertExist(privateKeyID string) *db.Cert {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=?", privateKeyID).First(&cert).Error; err != nil {
		return nil
	}
	return &cert
}

//GetCertById
func GetCertById(certId int) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("id=?", certId).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return &cert, nil
}
