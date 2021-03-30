package services

import (
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-go/common/helper"
)

func GetAndSaveNodeID(nodeTlsCrtFile []byte, certSN int64) (string, error) {
	nodeId := GetNodeID(certSN)
	if len(nodeId) > 0 {
		return nodeId, nil
	}
	nodeID, err := helper.GetLibp2pPeerIdFromCert(nodeTlsCrtFile)
	if nil != err {
		return "", fmt.Errorf("generate nodeID from file:[%v] failed:%v", nodeTlsCrtFile, err)
	}
	return SaveNodeID(nodeID, certSN)
}

func SaveNodeID(nodeId string, certSN int64) (string, error) {
	node := db.NodeId{ID: nodeId, CertSN: certSN}
	return nodeId, models.InsertNodeId(&node)
}

func GetNodeID(certSN int64) string {
	node, err := models.GetNodeId(certSN)
	if nil != err || nil == node {
		return ""
	}
	return node.ID
}
