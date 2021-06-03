/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//Insert keypair into the database
func InsertKeyPair(keyPair *db.KeyPair) error {
	if err := db.DB.Debug().Create(keyPair).Error; err != nil {
		return fmt.Errorf("[DB] create key pair error: %s", err.Error())
	}
	return nil
}

//Find keypair by ski
func FindKeyPairBySki(ski string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Debug().Where("ski=?", ski).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[DB] get key pair by ski failed: %s, ski: %s", err.Error(), ski)
	}
	return &keyPair, nil
}
