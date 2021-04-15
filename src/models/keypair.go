package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/crypto"
)

//InsertKeyPair .
func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return fmt.Errorf("[DB] create key pair error: %s", err.Error())
	}
	return nil
}

//GetKeyPairByID .
func GetKeyPairByID(id string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("id=?", id).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[DB] get key pair by id error: %s", err.Error())
	}
	return &keyPair, nil
}

//GetKeyPairByConditions .
func GetKeyPairByConditions(userID, orgID string, usage db.CertUsage, userType ...db.UserType) ([]db.KeyPair, error) {
	var keyPairList []db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_id=?", userID)
	}
	if orgID != "" {
		gorm = gorm.Where("org_id like ?", orgID+"%")
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

//KeyPairIsExist isExist
func KeyPairIsExist(userID, orgID string, usage db.CertUsage, userType ...db.UserType) (*db.KeyPair, bool) {
	var keyPair db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_id=?", userID)
	}
	if orgID != "" {
		gorm = gorm.Where("org_id like ?", orgID+"%")
	}
	if userType != nil {
		gorm = gorm.Where("user_type IN(?)", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.First(&keyPair).Error
	if err != nil {
		if err == db.GormErrRNF {
			return nil, false
		}
		return nil, true
	}
	return &keyPair, true
}

//KeyPairIsExistWithType isExist
func KeyPairIsExistWithType(userID, orgID, keyTypeStr string, usage db.CertUsage, userType ...db.UserType) (*db.KeyPair, bool) {
	var keyPair db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_id=?", userID)
	}
	if orgID != "" {
		gorm = gorm.Where("org_id like ?", orgID+"%")
	}
	if keyTypeStr != "" {
		gorm = gorm.Where("key_type=?", crypto.Name2KeyTypeMap[keyTypeStr])
	}
	if userType != nil {
		gorm = gorm.Where("user_type IN(?)", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.First(&keyPair).Error
	if err != nil {
		if err == db.GormErrRNF {
			return nil, false
		}
		return nil, true
	}
	return &keyPair, true
}

//GetKeyPairByConditions .
func GetIssuerKeyPairByConditions(userID, orgID string, privateKeyType int) (*db.KeyPair, error) {
	var keyPairList db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_type = 1 and org_id like ? and key_type=?", orgID+"%", privateKeyType)
	} else {
		gorm = gorm.Where("user_type = 0 and org_id = 'wx-root' and key_type=?", privateKeyType)
	}
	err := gorm.Find(&keyPairList).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] get issuer key pair by conditions error: %s, %s, %d", err.Error(), userID, privateKeyType)
	}
	return &keyPairList, nil
}

//GetIssuerKeyPairListByConditions .
func GetIssuerKeyPairListByConditions(userID, orgID string) ([]db.KeyPair, error) {
	var keyPairList []db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_type = 1 and org_id like ?", orgID+"%")
	} else {
		gorm = gorm.Where("user_type = 0 and org_id = 'wx-root'")
	}
	err := gorm.Find(&keyPairList).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] user get  issuer key pair by conditions error: %s", err.Error())
	}
	return keyPairList, nil
}

//GetUserKeyPairListByConditions .
func GetUserKeyPairListByConditions(userType int, userID, orgID string) ([]db.KeyPair, error) {
	var keyPairList []db.KeyPair
	gorm := db.DB.Debug()
	if userType != -1 {
		gorm = gorm.Where("user_type = ?", userType)
	}
	err := gorm.Where("org_id like ? and user_id=?", orgID+"%", userID).Find(&keyPairList).Error
	if err != nil {
		return nil, fmt.Errorf("[DB] user get key pair by conditions error: %s", err.Error())
	}
	return keyPairList, nil
}
