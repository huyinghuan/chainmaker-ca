package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"gorm.io/gorm"
)

func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return fmt.Errorf("[DB] create key pair error: %s", err.Error())
	}
	return nil
}

func MulInsertKeyPairs(keyPairs []*db.KeyPair) error {
	len := len(keyPairs)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(keyPairs, len).Error; err != nil {
			return fmt.Errorf("[DB] create multiple key pairs to db failed: %s", err.Error())
		}
		return nil
	})
	return err
}

func FindKeyPairBySki(ski string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("ski=?", ski).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[DB] get key pair by ski failed: %s, ski: %s", err.Error(), ski)
	}
	return &keyPair, nil
}
