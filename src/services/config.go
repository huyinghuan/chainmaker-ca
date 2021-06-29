/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import "chainmaker.org/chainmaker-ca-backend/src/utils"

const (
	//DEFAULT_CSR_COUNTRIY default csr country
	DEFAULT_CSR_COUNTRIY = "China"
	//DEFAULT_CSR_LOCALITY default csr locality
	DEFAULT_CSR_LOCALITY = "Beijing"
	//DEFAULT_CSR_PROVINCE default csr province
	DEFAULT_CSR_PROVINCE = "Beijing"
)

//The port number in the configuration file
func ServerPortFromConfig() string {
	if len(allConfig.GetServerPort()) == 0 {
		return ":8090"
	}
	return ":" + allConfig.GetServerPort()
}

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

//IsAccessControlFromConfig whether access control is enabled in the configuration file
func IsAccessControlFromConfig() bool {
	return allConfig.IsAccessControl()
}

func rootCertConfFromConfig() []*utils.CertConf {
	return allConfig.GetRootCertConf()
}

func isUseAccessControlFromConfig() bool {
	return allConfig.IsAccessControl()
}

func accessControlFromConfig() []*utils.AccessControlConf {
	return allConfig.GetAccessControlConf()
}
