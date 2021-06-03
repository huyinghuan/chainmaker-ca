/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"testing"

	"chainmaker.org/chainmaker-ca-backend/src/utils"
)

//Test database initialization
func TestDBInit(t *testing.T) {

	utils.SetConfig(utils.GetConfigEnv())
	DBInit()
}
