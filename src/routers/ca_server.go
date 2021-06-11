/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package routers

import (
	"chainmaker.org/chainmaker-ca-backend/src/handlers"
	"github.com/gin-gonic/gin"
)

const ROUTERS_HEADER = "/api/ca"

func LoadCAServerRouter(e *gin.Engine) {
	e.POST(ROUTERS_HEADER+"/gencertbycsr", handlers.GenCertByCsr())
	e.POST(ROUTERS_HEADER+"/gencert", handlers.GenCert())
	e.POST(ROUTERS_HEADER+"/querycerts", handlers.QueryCerts())
	e.POST(ROUTERS_HEADER+"/renewcert", handlers.RenewCert())
	e.POST(ROUTERS_HEADER+"/revokecert", handlers.RevokeCert())
	e.POST(ROUTERS_HEADER+"/gencrl", handlers.GenCrl())
	e.POST(ROUTERS_HEADER+"/gencsr", handlers.GenCsr())
}
