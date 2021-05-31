package utils

import (
	"fmt"
	"testing"
)

func TestInitConf(t *testing.T) {
	SetConfig(GetConfigEnv())
}

func TestGetAllConf(t *testing.T) {
	TestInitConf(t)
	allConf := GetAllConfig()

	fmt.Printf("base config: %v\n", allConf.GetBaseConf())
	fmt.Printf("root config: %v\n", allConf.GetRootConf())
	for _, v := range allConf.GetIntermediateConf() {
		fmt.Printf("Intermediate ca config: %v\n", v)
	}
	fmt.Printf("double root config: %v\n", allConf.GetDoubleRootPathConf())
}

func TestGetSomeConf(t *testing.T) {
	TestInitConf(t)
	allConf := GetAllConfig()
	hashType := allConf.GetHashType()
	keyType := allConf.GetKeyType()
	fmt.Printf("hash type :%s\n", hashType)
	fmt.Printf("key type :%s\n", keyType)
}
