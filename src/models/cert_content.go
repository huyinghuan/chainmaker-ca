/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//Inserts the certcontent into the database
func InsertCertContent(certContent *db.CertContent) error {
	if err := db.DB.Debug().Create(certContent).Error; err != nil {
		return fmt.Errorf("[DB] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
	}
	return nil
}

//Find certcontent by Sn
func FindCertContentBySn(sn int64) (*db.CertContent, error) {
	var certContent db.CertContent
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certContent).Error; err != nil {
		return nil, fmt.Errorf("[DB] find cert content by sn error: %s, sn: %d", err.Error(), sn)
	}
	return &certContent, nil
}

//Check to see if the certificate exists
func IsCertContentExist(sn int64) *db.CertContent {
	var certContent db.CertContent
	if err := db.DB.Debug().Where("serial_number=?", sn).First(&certContent).Error; err != nil {
		return nil
	}
	return &certContent
}

//Update cert content
func UpdateCertContent(oldCertContent, newCertContent *db.CertContent) error {
	if err := db.DB.Model(oldCertContent).Select("content", "cert_raw", "key_usage", "ext_key_usage", "is_ca", "issue_date", "invalid_date").
		Updates(newCertContent).Error; err != nil {
		return fmt.Errorf("[DB] update cert content failed: %s", err.Error())
	}
	return nil
}
