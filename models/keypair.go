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
func GetKeyPairByConditions(userID, orgID, chainID string, userType db.UserType, usage db.CertUsage) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	gorm := db.DB.Debug()
	if userID != "" {
		gorm = gorm.Where("user_id=?", userID)
	}
	if orgID != "" {
		gorm = gorm.Where("org_id=?", orgID)
	}
	if chainID != "" {
		gorm = gorm.Where("chain_id=?", chainID)
	}
	if userType != -1 {
		gorm = gorm.Where("user_type=?", userType)
	}
	if usage != -1 {
		gorm = gorm.Where("cert_usage=?", usage)
	}
	err := gorm.First(&keyPair).Error
	if err != nil {
		return nil, err
	}
	return &keyPair, nil
}
