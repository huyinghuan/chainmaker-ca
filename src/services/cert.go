package services

// import (
// 	"chainmaker.org/chainmaker-ca-backend/src/models"
// 	"chainmaker.org/chainmaker-ca-backend/src/models/db"
// )

// //GetCertByConditions
// func GetCertByConditions(userId, orgId string, usage db.CertUsage, userType ...db.UserType) ([]*db.Cert, error) {
// 	keyPairList, err := models.GetKeyPairByConditions(userId, orgId, usage, userType...)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(keyPairList) == 0 {
// 		return nil, nil
// 	}
// 	var certList []*db.Cert
// 	for i := 0; i < len(keyPairList); i++ {
// 		cert, err := models.GetCertByPrivateKeyID(keyPairList[i].Id)
// 		if err != nil {
// 			return nil, err
// 		}
// 		certList = append(certList, cert)
// 	}
// 	return certList, nil
// }
