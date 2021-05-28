package services

import (
	"fmt"
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
)

func TestFindCertInfoByConditions(t *testing.T) {
	InitDB()
	InitServer()
	certInfoList, err := models.FindCertInfoByConditions("org2_2", "org2", 1, 3, 2)
	if err != nil {
		fmt.Print("FindCertInfoByConditions")
	}
	var res []*db.CertContent
	for index, value := range certInfoList {
		tmp, err := models.FindCertContentBySn(value.SerialNumber)
		if err != nil {
			return
		}
		fmt.Println(index)
		res = append(res, tmp)
	}

}
