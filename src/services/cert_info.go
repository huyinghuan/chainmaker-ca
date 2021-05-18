package services

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/helper"
)

type CertConditions


func CreateCertInfo(certContent *db.CertContent, keyPair *db.KeyPair)

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
