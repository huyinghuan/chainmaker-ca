package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func InsertCertInfo(certInfo *db.CertInfo) error {
	if err := db.DB.Debug().Create(certInfo).Error; err != nil {
		return fmt.Errorf("[DB] create cert info to db failed: %s, sn: %d", err.Error(), certInfo.SerialNumber)
	}
	return nil
}

func FindCertInfoBySn(sn int64) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certInfo).Error; err != nil {
		return nil, fmt.Errorf("[DB] find cert infos by sn error: %s, sn: %d", err.Error(), sn)
	}
	return &certInfo, nil
}

func IsCertInfoExist(sn int64) *db.CertInfo {
	var certInfo db.CertInfo
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certInfo).Error; err != nil {
		return nil
	}
	return &certInfo
}

func FindCertInfoByPrivateKey(privateKeyId string) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	if err := db.DB.Debug().Where("private_key_id=?", privateKeyId).First(&certInfo).Error; err != nil {
		return nil, fmt.Errorf("[DB] find cert infos by private key id failed: %s, private key id: %s", err.Error(), privateKeyId)
	}
	return &certInfo, nil
}

func FindCertInfoByIssuerSn(issuerSn int64) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	if err := db.DB.Debug().Where("issure_sn=?", issuerSn).First(&certInfo).Error; err != nil {
		return nil, fmt.Errorf("[DB] find cert infos by issuer sn failed: %s, issuer sn: %d", err.Error(), issuerSn)
	}
	return &certInfo, nil
}
func FindActiveCertInfoByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	tx := db.DB.Debug().Where("cert_status = ?", db.ACTIVE)
	if userId != "" {
		tx.Where("user_id=?", userId)
	}
	if orgId != "" {
		tx.Where("org_id=?", orgId)
	}
	if userType != 0 {
		tx.Where("user_type =?", userType)
	}
	if usage != 0 {
		tx.Where("cert_usage=?", usage)
	}
	err := tx.First(&certInfo).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] find cert info by conditions failed: %s", err.Error())
	}
	return &certInfo, nil
}

func UpdateCertInfoBySn(certInfo *db.CertInfo, sn int64) error {
	if err := db.DB.Debug().Model(&db.CertInfo{}).
		Where("SerialNumber=?", certInfo.SerialNumber).Update("SerialNumber", sn).Error; err != nil {
		err = fmt.Errorf("[DB] find cert info by sn failed: %s", err.Error())
		return err
	}
	return nil
}

func FindCertInfoByConditions(userId, orgId string, usage db.CertUsage, userType db.UserType, certStatus db.CertStatus) ([]*db.CertInfo, error) {
	var certInfos []*db.CertInfo
	tx := db.DB.Debug()
	if userId != "" {
		tx = tx.Where("user_id=?", userId)
	}
	if orgId != "" {
		tx = tx.Where("org_id=?", orgId)
	}
	if userType != 0 {
		tx = tx.Where("user_type =?", userType)
	}
	if usage != 0 {
		tx = tx.Where("cert_usage=?", usage)
	}
	if certStatus != 0 {
		tx = tx.Where("cert_status=?", certStatus)
	}
	err := tx.Find(&certInfos).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] find cert info by conditions failed: %s", err.Error())
	}
	return certInfos, nil
}
