package models

import (
	"fmt"
	"strconv"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

//InsertCert 插入证书
func InsertCert(cert *db.Cert) error {
	if err := db.DB.Debug().Create(cert).Error; err != nil {
		return fmt.Errorf("[DB] create cert error: %s", err.Error())
	}
	return nil
}

//GetCertBySN .
func GetCertBySN(certSN int64) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("serial_number=?", certSN).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return &cert, nil
}

//UpdateCertStatusRevokedBySN 通过证书SN
func UpdateCertStatusRevokedBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=?", certSN).Update("cert_status", db.REVOKED).Error; err != nil {
		return fmt.Errorf("[DB] update cert status revoked by sn error: %s", err.Error())
	}
	return nil
}

//UpdateCertStatusExpiredBySN 通过证书SN
func UpdateCertStatusExpiredBySN(certSN int64) error {
	if err := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=?", certSN).Update("cert_status", db.EXPIRED).Error; err != nil {
		return fmt.Errorf("[DB] update cert status expired by sn error: %s", err.Error())
	}
	return nil
}

//GetCertByPrivateKeyID .
func GetCertByPrivateKeyID(privateKeyID string) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=? AND cert_status=?", privateKeyID, db.EFFECTIVE).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by private key id error: %s, %s", err.Error(), privateKeyID)
	}
	return &cert, nil
}

//GetCertByPrivateKeyIDWithOutStatus .
func GetCertByPrivateKeyIDWithOutStatus(privateKeyID string) ([]db.Cert, error) {
	var certs []db.Cert
	if err := db.DB.Debug().Table("cert").Where("private_key_id=?", privateKeyID).Scan(&certs).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by private key id error: %s, %s", err.Error(), privateKeyID)
	}
	return certs, nil
}

//CertIsExist .
func CertIsExist(privateKeyID string) (*db.Cert, bool) {
	var cert db.Cert
	if err := db.DB.Debug().Where("private_key_id=?", privateKeyID).First(&cert).Error; err != nil {
		if err == db.GormErrRNF {
			return nil, false
		}
		return nil, true
	}
	return &cert, true
}

func GetCertById(certId int) (*db.Cert, error) {
	var cert db.Cert
	if err := db.DB.Debug().Where("id=?", certId).First(&cert).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return &cert, nil
}

func GetCertByOrgId(orgId string) ([]db.Cert, error) {
	var certs []db.Cert
	if err := db.DB.Debug().Table("cert").Where("organization=?", orgId).Scan(&certs).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return certs, nil
}

func GetCertRespyOrgId(orgId string) ([]CertResp, error) {
	var certs []CertResp
	if err := db.DB.Debug().Table("cert").Where("organization=?", orgId).Scan(&certs).Error; err != nil {
		return nil, fmt.Errorf("[DB] get cert by sn error: %s", err.Error())
	}
	return certs, nil
}

//InsertNodeId nodeId
func InsertNodeId(nodeId *db.NodeId) error {
	if err := db.DB.Debug().Create(nodeId).Error; err != nil {
		return fmt.Errorf("[DB] create nodeId error: %s, %s, %s", err.Error(), strconv.FormatInt(nodeId.CertSN, 10), nodeId.ID)
	}
	return nil
}

//GetNodeId nodeId
func GetNodeId(certSN int64) (*db.NodeId, error) {
	var node db.NodeId
	if err := db.DB.Debug().Where("cert_sn=?", certSN).First(&node).Error; err != nil {
		return nil, fmt.Errorf("[DB] get nodeId error: %s, %s", err.Error(), strconv.FormatInt(certSN, 10))
	}
	return &node, nil
}

//UpdateCertBySN .
func UpdateCertBySN(certSN int64, old_cert_status, new_cert_status int) error {
	var total int64
	g := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=? and cert_status=?", certSN, old_cert_status)
	if err := g.Count(&total).Error; err != nil {
		return fmt.Errorf("[DB] update cert by sn error: %s", err.Error())
	}
	if total <= 0 {
		return fmt.Errorf("[DB] update cert by sn error: no recording")
	}
	if err := g.Update("cert_status", new_cert_status).Error; err != nil {
		return fmt.Errorf("[DB] update cert by sn error: %s", err.Error())
	}
	return nil
}

//GetCertsByConditions .
func GetCertsByConditions(OrgId, UserId string, start, pageSize, UserStatus, Id, CertType, UserType int, startTime, endTime int64) ([]CertResp, int64, error) {
	CertResp := make([]CertResp, 0)
	gorm := db.DB.Debug().Table("cert")
	gorm = gorm.Select("cert.organization as org_id, cert.invalid_date as invalid_date, cert.cert_status as user_status, cert.id as id, key_pair.user_id as ou, cert.serial_number as cert_sn, key_pair.user_type as user_type, key_pair.cert_usage as cert_type")
	if startTime != -1 {
		gorm = gorm.Table("cert").Where("cert.issue_date>=?", startTime)
	}
	if endTime != -1 {
		gorm = gorm.Table("cert").Where("cert.issue_date<=?", endTime)
	}
	if Id != -1 {
		gorm = gorm.Where("cert.id=?", Id).Joins("join key_pair on key_pair.id = cert.private_key_id").Where("key_pair.user_type<>0")
	} else {
		gorm = gorm.Where("key_pair.user_id <>'client1' and key_pair.user_id <>'admin1'")
		if OrgId != "" {
			gorm = gorm.Where("cert.organization like ?", OrgId+"%")
		}

		if UserId != "" {
			gorm = gorm.Where("key_pair.user_id =?", UserId)
		}

		if UserStatus != -1 {
			gorm = gorm.Where("cert.cert_status=?", UserStatus)
		}
		gorm = gorm.Joins("inner join key_pair on key_pair.id = cert.private_key_id").Where("key_pair.user_type<>0")

		if CertType != -1 {
			gorm = gorm.Where("key_pair.cert_usage=?", CertType)
		}
		if UserType != -1 {
			gorm = gorm.Where("key_pair.user_type=?", UserType)
		} else {
			gorm = gorm.Where("key_pair.user_type>=1 and key_pair.user_type<4")
		}
	}

	var total int64
	err := gorm.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}
	if start > 0 {
		gorm = gorm.Offset(start)
	}
	if pageSize > 0 {
		gorm = gorm.Limit(pageSize)
	}
	err = gorm.Scan(&CertResp).Error
	if err != nil {
		return nil, 0, fmt.Errorf("[DB] get certs by conditions error: %s", err.Error())
	}
	return CertResp, total, nil
}

//CheckCertBySNAndOrgId .
func CheckCertBySNAndOrgId(certSN int64, organization string) bool {
	var total int
	if err := db.DB.Debug().Model(&db.Cert{}).Where("serial_number=? and organization=?", certSN, organization).Count(&total).Error; err == nil && total > 0 {
		return true
	}
	return false
}
