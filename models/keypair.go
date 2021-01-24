package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertKeyPair .
func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return err
	}
	return nil
}

//GetKeyPairByID .
func GetKeyPairByID(id string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("id=?", id).First(&keyPair).Error; err != nil {
		return nil, err
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
		gorm = gorm.Where("org_id=?", orgID)
	}
	if userType != nil {
		gorm = gorm.Where("user_type IN(?)", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.Find(&keyPairList).Error
	if err != nil {
		return nil, err
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
		gorm = gorm.Where("org_id=?", orgID)
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
