package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitConf(t *testing.T) {
	SetConfig(GetConfigEnv())
}

func TestGetAllConf(t *testing.T) {
	TestInitConf(t)
	allConf := GetAllConfig()

	fmt.Printf("base config: %v\n", allConf.BaseConf)
	fmt.Printf("root config: %v\n", allConf.RootCaConf)
	for _, v := range allConf.IntermediateCaConf {
		fmt.Printf("Intermediate ca config: %v\n", v)
	}
	fmt.Printf("double root config: %v\n", allConf.DoubleRootPathConf)
}

func TestGetConf(t *testing.T) {
	TestInitConf(t)
	baseConf, err := GetBaseConf()
	require.Nil(t, err)
	rootConf, err := GetRootCaConf()
	require.Nil(t, err)
	intermediateCaConf, err := GetIntermediateCaConf()
	require.Nil(t, err)
	doubleRootConf, err := GetDoubleRootPathConf()
	require.Nil(t, err)

	fmt.Printf("base config: %v\n", baseConf)
	fmt.Printf("root config: %v\n", rootConf)
	for _, v := range intermediateCaConf {
		fmt.Printf("Intermediate ca config: %v\n", v)
	}
	fmt.Printf("double root config: %v\n", doubleRootConf)
}

func TestGetSomeConf(t *testing.T) {
	TestInitConf(t)
	allConf := GetAllConfig()
	hashType := allConf.GetHashType()
	keyType := allConf.GetKeyType()
	fmt.Printf("hash type :%s\n", hashType)
	fmt.Printf("key type :%s\n", keyType)
}
