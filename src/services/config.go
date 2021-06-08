/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import "chainmaker.org/chainmaker-ca-backend/src/utils"

const (
	DEFAULT_CSR_COUNTRIY   = "China"
	DEFAULT_CSR_LOCALITY   = "Beijing"
	DEFAULT_CSR_PROVINCE   = "Beijing"
	DEFAULT_SIGN_CERT_PATH = "./crypto-config/rootCA/sign/root.crt"
	DEFAULT_SIGN_KEY_PATH  = "./crypto-config/rootCA/sign/root.key"
	DEFAULT_TLS_CERT_PATH  = "./crypto-config/rootCA/tls/root.crt"
	DEFAULT_TLS_KEY_PATH   = "./crypto-config/rootCA/tls/root.key"
)

func rootCaConfFromConfig() *utils.CaConfig {
	return allConfig.GetRootConf()
}

func imCaConfFromConfig() []*utils.ImCaConfig {
	return allConfig.GetIntermediateConf()
}

func canIssueCa() bool {
	return allConfig.GetCanIssueCa()
}

func provideServiceFor() []string {
	return allConfig.GetProvideServiceFor()
}
func hashTypeFromConfig() string {
	return allConfig.GetHashType()
}

func keyTypeFromConfig() string {
	return allConfig.GetKeyType()
}

func expireYearFromConfig() int {
	return allConfig.GetDefaultExpireTime()
}

func isKeyEncryptFromConfig() bool {
	return allConfig.IsKeyEncrypt()
}

func rootCertConfFromConfig() []*utils.CertConf {
	return allConfig.GetRootCertConf()
}

func rootCsrConfFromConfig() *utils.CsrConf {
	return allConfig.GetRootCsrConf()
}
