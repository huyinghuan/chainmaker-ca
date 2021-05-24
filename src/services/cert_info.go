package services

import (
	"encoding/base64"
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/helper"
)

type CertConditions struct {
	UserType  db.UserType
	CertUsage db.CertUsage
	UserId    string
	OrgId     string
}

func CreateCertInfo(certContent *db.CertContent, privateKeyId string, conditions *CertConditions) (*db.CertInfo, error) {
	_, err := models.FindCertInfoByConditions(conditions.UserId, conditions.OrgId, conditions.CertUsage, conditions.UserType)
	if err == nil {
		return nil, fmt.Errorf("create cert info faield: cert info is exist")
	}
	aki := certContent.Aki
	var issueCertSn int64
	if len(aki) != 0 {

		issueCertInfo, err := models.FindCertInfoByPrivateKey(aki)
		if err != nil {
			return nil, err
		}
		issueCertSn = issueCertInfo.SerialNumber
	}
	certBytes, err := base64.StdEncoding.DecodeString(certContent.Content)
	if err != nil {
		return nil, err
	}

	p2pNodeId, err := GetP2pNetNodeId(conditions.UserType, conditions.CertUsage, certBytes)
	if err != nil {
		return nil, err
	}
	certInfo := &db.CertInfo{
		SerialNumber: certContent.SerialNumber,
		PrivateKeyId: privateKeyId,
		CertStatus:   db.ACTIVE,
		IssuerSn:     issueCertSn,
		P2pNodeId:    p2pNodeId,
		UserType:     conditions.UserType,
		CertUsage:    conditions.CertUsage,
		OrgId:        conditions.OrgId,
		UserId:       conditions.UserId,
	}
	return certInfo, nil
}

func GetP2pNetNodeId(userType db.UserType, certUsage db.CertUsage, nodeTlsCrtBytes []byte) (string, error) {
	var (
		p2pNodeId string
		err       error
	)
	if (userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS) &&
		(certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN) {
		p2pNodeId, err = helper.GetLibp2pPeerIdFromCert(nodeTlsCrtBytes)
		if err != nil {
			return p2pNodeId, fmt.Errorf("[Get p2p nodeId] get libp2p peer id from cert error :%s", err.Error())
		}
	}
	return p2pNodeId, nil
}
