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

//GetCertBySN .
func GetCertBySN(certSN int64) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("serial_number=?", certSN).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

//UpdateCertStatusRevokedBySN 通过证书SN
func UpdateCertStatusRevokedBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Update("cert_status", db.REVOKED).Where("serial_number", certSN).Error; err != nil {
		return err
	}
	return nil
}

//GetCertByUserType .
func GetCertByUserType(userID int, certType db.CertType) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("user_id=? AND cert_type=?", userID, certType).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

//GetCertByNodeNameUsage .
func GetCertByNodeNameUsage(nodeName string, usage db.CertUsage, chainID, consortiumID string) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("node_name=? AND cert_usage=? AND chain_id=? AND consortium_id=?", nodeName, usage, chainID, consortiumID).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

//GetCertByUserTypeChain .
func GetCertByUserTypeChain(userID int, certType db.CertType, usage db.CertUsage, chainID, consortiumID string) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("user_id=? AND cert_type=? AND chain_id=? AND consortium_id=? AND cert_usage=?", userID, certType, chainID, consortiumID, usage).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}
