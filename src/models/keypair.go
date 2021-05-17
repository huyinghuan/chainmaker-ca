package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//InsertKeyPair
func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return fmt.Errorf("[DB] create key pair error: %s", err.Error())
	}
	return nil
}

//GetKeyPairByID
func GetKeyPairByID(id string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("id=?", id).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[DB] get key pair by id error: %s", err.Error())
	}
	return &keyPair, nil
}

//GetKeyPairByConditions
func GetKeyPairByConditions(userId, orgId string, usage db.CertUsage, userType ...db.UserType) ([]db.KeyPair, error) {
	var keyPairList []db.KeyPair
	gorm := db.DB.Debug()
	if userId != "" {
		gorm = gorm.Where("user_id=?", userId)
	}
	if orgId != "" {
		gorm = gorm.Where("org_id=?", orgId)
	}
	if userType != nil {
		gorm = gorm.Where("user_type IN(?)", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.Find(&keyPairList).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] get key pair by conditions error: %s", err.Error())
	}
	return keyPairList, nil
}

//IsKeyPairExist
func IsKeyPairExist(userId, orgId string, usage db.CertUsage, userType ...db.UserType) *db.KeyPair {
	var keyPair db.KeyPair
	gorm := db.DB.Debug()
	if userId != "" {
		gorm = gorm.Where("user_id=?", userId)
	}
	if orgId != "" {
		gorm = gorm.Where("org_id=?", orgId)
	}
	if userType != nil {
		gorm = gorm.Where("user_type IN(?)", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.First(&keyPair).Error
	if err != nil {
		return nil
	}
	return &keyPair
}
