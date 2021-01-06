package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertKeyPair .
func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return err
	}
	return nil
}

//GetKeyPairByUserID .
func GetKeyPairByUserID(userID int) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("user_id=?", userID).First(&keyPair).Error; err != nil {
		return nil, err
	}
	return &keyPair, nil
}
