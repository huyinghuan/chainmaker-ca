package db

import (
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/utils"
)

//

func TestDBInit(t *testing.T) {

	utils.SetConfig(utils.GetConfigEnv())
	DBInit()
}
