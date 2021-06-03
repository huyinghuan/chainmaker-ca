/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//Inset revokedcert into database
func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Debug().Create(revokedCert).Error; err != nil {
		return fmt.Errorf("[DB] create revoked cert info failed: %s", err.Error())
	}
	return nil
}

//Query revokedcert by issuesn
func QueryRevokedCertByIssueSn(sn int64) ([]*db.RevokedCert, error) {
	var revokedCerts []*db.RevokedCert
	err := db.DB.Debug().Model(&db.RevokedCert{}).Where("revoked_by=?", sn).Find(&revokedCerts).Error
	if err != nil {
		return nil, err
	}
	return revokedCerts, nil
}

//Query revokedcert by revokedsn
func QueryRevokedCertByRevokedSn(sn int64) (*db.RevokedCert, error) {
	var revokedCert *db.RevokedCert
	err := db.DB.Debug().Model(&db.RevokedCert{}).Where("revoked_cert_sn=?", sn).First(&revokedCert).Error
	if err != nil {
		return nil, err
	}
	return revokedCert, nil
}
