package services

import (
	"fmt"
	"testing"
)

func TestProductIntermediateCA(t *testing.T) {
	InitDB()
	InitServer()
	err := CreateIntermediateCA()
	if err != nil {
		fmt.Println(err.Error())
	}
}
