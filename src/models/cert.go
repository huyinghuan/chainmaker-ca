package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//InsertCert 插入证书
func InsertCert(cert *db.Cert) error {
	if err := db.DB.Debug().Create(cert).Error; err != nil {
		return fmt.Errorf("[DB] create cert error: %s", err.Error())
	}
	return nil
}

//GetCertBySN .
func GetCertBySN(certSN int64) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("serial_number=?", certSN).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return &cert, nil
}

//UpdateCertStatusRevokedBySN 通过证书SN
func UpdateCertStatusRevokedBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Update("cert_status", db.REVOKED).Where("serial_number", certSN).Error; err != nil {
		return fmt.Errorf("[DB] update cert status revoked by sn error: %s", err.Error())
	}
	return nil
}

//UpdateCertStatusExpiredBySN 通过证书SN
func UpdateCertStatusExpiredBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Update("cert_status", db.EXPIRED).Where("serial_number", certSN).Error; err != nil {
		return fmt.Errorf("[DB] update cert status expired by sn error: %s", err.Error())
	}
	return nil
}

//GetCertByPrivateKeyID .
func GetCertByPrivateKeyID(privateKeyID string) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=? AND cert_status=?", privateKeyID, db.EFFECTIVE).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by private key id error: %s", err.Error())
	}
	return &cert, nil
}

//CertIsExist .
func CertIsExist(privateKeyID string) (*db.Cert, bool) {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=?", privateKeyID).First(&cert).Error; err != nil {
		if err == db.GormErrRNF {
			return nil, false
		}
		return nil, true
	}
	return &cert, true
}
