package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return fmt.Errorf("[DB] create key pair error: %s", err.Error())
	}
	return nil
}

func FindKeyPairBySki(ski string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("ski=?", ski).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[DB] get key pair by ski failed: %s, ski: %s", err.Error(), ski)
	}
	return &keyPair, nil
}
