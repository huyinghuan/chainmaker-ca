/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"flag"
	"fmt"
	"os"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"github.com/spf13/viper"
)

var allConf *AllConfig

type AllConfig struct {
	LogConf            *loggers.LogConifg `mapstructure:"log_config"`
	DBConf             *DBConfig          `mapstructure:"db_config"`
	BaseConf           *BaseConf          `mapstructure:"base_config"`
	RootCaConf         *CaConfig          `mapstructure:"root_config"`
	IntermediateCaConf []*ImCaConfig      `mapstructure:"intermediate_config"`
}

type BaseConf struct {
	CaType            string   `mapstructure:"ca_type"`
	ExpireYear        int      `mapstructure:"expire_year"`
	HashType          string   `mapstructure:"hash_type"`
	KeyType           string   `mapstructure:"key_type"`
	CanIssueca        bool     `mapstructure:"can_issue_ca"`
	ProvideServiceFor []string `mapstructure:"provide_service_for"`
	IsKeyEncrypt      bool     `mapstructure:"key_encrypt"`
}

type CaConfig struct {
	CsrConf  *CsrConf    `mapstructure:"csr"`
	CertConf []*CertConf `mapstructure:"cert"`
}

type ImCaConfig struct {
	CsrConf       *CsrConf `mapstructure:"csr"`
	PrivateKeyPwd string   `mapstructure:"private_key_pwd"`
}

type CsrConf struct {
	CN       string `mapstructure:"CN"`
	O        string `mapstructure:"O"`
	OU       string `mapstructure:"OU"`
	Country  string `mapstructure:"country"`
	Locality string `mapstructure:"locality"`
	Province string `mapstructure:"province"`
}

type CertConf struct {
	CertType       string `mapstructure:"cert_type"`
	CertPath       string `mapstructure:"cert_path"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
}

// GetConfigEnv --Specify the path and name of the configuration file (Env)
func GetConfigEnv() string {
	var env string
	n := len(os.Args)
	for i := 1; i < n-1; i++ {
		if os.Args[i] == "-e" || os.Args[i] == "--env" {
			env = os.Args[i+1]
			break
		}
	}
	fmt.Println("[env]:", env)
	if env == "" {
		fmt.Println("env is empty, set default")
		env = ""
	}
	return env
}

//GetFlagPath --Specify the path and name of the configuration file (flag)
func GetFlagPath() string {
	var configPath string
	flag.StringVar(&configPath, "config", "./conf/config.yaml", "please input config file path")
	flag.Parse()
	return configPath
}

//SetConfig --Set config path and file name
func SetConfig(envPath string) {
	var configPath string
	if envPath != "" {
		configPath = envPath
	} else {
		configPath = GetFlagPath()
	}
	InitConfig(configPath)
}

//InitConfig --init config
func InitConfig(configPath string) {
	viper.SetConfigFile(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	allConf, err = GetAllConf()
	if err != nil {
		panic(err)
	}
	err = loggers.InitLogger(allConf.GetLogConf())
	if err != nil {
		panic(err)
	}
}

//DBConfig /
type DBConfig struct {
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	IP       string `mapstructure:"ip"`
	Port     string `mapstructure:"port"`
	DbName   string `mapstructure:"dbname"`
}

//GetDBConfig --Get DB config from config file.
func GetDBConfig() string {
	dbConfig := allConf.GetDBConf()
	mysqlURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		dbConfig.User, dbConfig.Password, dbConfig.IP, dbConfig.Port, dbConfig.DbName, "utf8")
	return mysqlURL
}

//Get all conf
func GetAllConf() (*AllConfig, error) {
	var allConf AllConfig
	err := viper.Unmarshal(&allConf)
	if err != nil {
		return nil, fmt.Errorf("get all config failed: %s", err.Error())
	}
	if allConf.DBConf == nil {
		return nil, fmt.Errorf("get all config failed: not found db config")
	}
	if allConf.BaseConf == nil {
		return nil, fmt.Errorf("get all config failed: not found base config")
	}
	if allConf.RootCaConf == nil {
		return nil, fmt.Errorf("get all config failed: not found root config")
	}
	return &allConf, nil
}

func GetAllConfig() *AllConfig {
	return allConf
}

func (ac *AllConfig) GetHashType() string {
	return ac.BaseConf.HashType
}

func (ac *AllConfig) GetKeyType() string {
	return ac.BaseConf.KeyType
}

func (ac *AllConfig) GetDefaultExpireTime() int {
	return ac.BaseConf.ExpireYear
}

func (ac *AllConfig) GetCanIssueCa() bool {
	return ac.BaseConf.CanIssueca
}

func (ac *AllConfig) GetProvideServiceFor() []string {
	return ac.BaseConf.ProvideServiceFor
}

func (ac *AllConfig) IsKeyEncrypt() bool {
	return ac.BaseConf.IsKeyEncrypt
}

func (ac *AllConfig) GetCaType() string {
	return ac.BaseConf.CaType
}

func (ac *AllConfig) GetRootConf() *CaConfig {
	return ac.RootCaConf
}

func (ac *AllConfig) GetRootCsrConf() *CsrConf {
	return ac.RootCaConf.CsrConf
}

func (ac *AllConfig) GetRootCertConf() []*CertConf {
	return ac.RootCaConf.CertConf
}

func (ac *AllConfig) GetBaseConf() *BaseConf {
	return ac.BaseConf
}

func (ac *AllConfig) GetIntermediateConf() []*ImCaConfig {
	return ac.IntermediateCaConf
}

func (ac *AllConfig) GetLogConf() *loggers.LogConifg {
	return ac.LogConf
}

func (ac *AllConfig) GetDBConf() *DBConfig {
	return ac.DBConf
}
