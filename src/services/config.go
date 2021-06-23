/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import "chainmaker.org/chainmaker-ca-backend/src/utils"

const (
	DEFAULT_CSR_COUNTRIY = "China"
	DEFAULT_CSR_LOCALITY = "Beijing"
	DEFAULT_CSR_PROVINCE = "Beijing"
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

func IsAccessControlFromConfig() bool {
	return allConfig.IsAccessControl()
}

func rootCertConfFromConfig() []*utils.CertConf {
	return allConfig.GetRootCertConf()
}

func rootCsrConfFromConfig() *utils.CsrConf {
	return allConfig.GetRootCsrConf()
}

func isUseAccessControlFromConfig() bool {
	return allConfig.IsAccessControl()
}

func accessControlFromConfig() []*utils.AccessControlConf {
	return allConfig.GetAccessControlConf()
}
