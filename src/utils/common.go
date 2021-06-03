/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"time"

	"chainmaker.org/chainmaker-go/common/crypto"
)

const (
	DefaultPrivateKeyPwd = "d02f421ed76e0e26e9def824a8b84c7c223d484762d6d060a8b71e1649d1abbf"

	DefaultWorkDirectory = "./"

	DefaultCRLNextTime = time.Hour
)

var HashType2NameMap = map[crypto.HashType]string{
	crypto.HASH_TYPE_SM3:      "SM3",
	crypto.HASH_TYPE_SHA256:   "SHA256",
	crypto.HASH_TYPE_SHA3_256: "SHA3_256",
}

var Name2HashTypeMap = map[string]crypto.HashType{
	"SM3":      crypto.HASH_TYPE_SM3,
	"SHA256":   crypto.HASH_TYPE_SHA256,
	"SHA3_256": crypto.HASH_TYPE_SHA3_256,
}

type CaType int

const (
	TLS CaType = iota + 1
	SIGN
	SINGLE_ROOT
	DOUBLE_ROOT
)

//CaType2NameMap Ca type to string name
var CaType2NameMap = map[CaType]string{
	TLS:         "tls",
	SIGN:        "sign",
	SINGLE_ROOT: "single_root",
	DOUBLE_ROOT: "double_root",
}

//Name2CaTypeMap string name to ca type
var Name2CaTypeMap = map[string]CaType{
	"tls":         TLS,
	"sign":        SIGN,
	"solo_root":   SINGLE_ROOT,
	"double_root": DOUBLE_ROOT,
}
