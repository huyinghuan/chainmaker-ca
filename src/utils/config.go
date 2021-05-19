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
	logConf            *loggers.LogConifg  `mapstructure:"log_config"`
	dbConf             *DBConfig           `mapstructure:"db_config"`
	baseConf           *BaseConf           `mapstructure:"base_config"`
	rootCaConf         *CaConfig           `mapstructure:"root_config"`
	intermediateCaConf []*CaConfig         `mapstructure:"Intermediate_config"`
	doubleRootPathConf *DoubleRootPathConf `mapstructure:"rootpath_double"`
}

type BaseConf struct {
	CaType            string   `mapstructure:"ca_type"`
	ExpireYear        int      `mapstructure:"expire_year"`
	HashType          string   `mapstructure:"hash_type"`
	KeyType           string   `mapstructure:"key_type"`
	CanIssueca        bool     `mapstructure:"can_issue_ca"`
	ProvideServiceFor []string `mapstructure:"provide_service_for"`
}

type CaConfig struct {
	CsrConf  *CsrConf  `mapstructure:"csr"`
	CertConf *CertConf `mapstructure:"cert"`
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
	CertPath       string `mapstructure:"cert_path"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	PrivateKeyPwd  string `mapstructure:"private_key_pwd"`
}

type DoubleRootPathConf struct {
	TlsCertPath        string `mapstructure:"tls_cert_path"`
	TlsPrivateKeyPath  string `mapstructure:"tls_privatekey_path"`
	TlsPrivateKeyPwd   string `mapstructure:"tls_privatekey_pwd"`
	SignCertPath       string `mapstructure:"sign_cert_path"`
	SignPrivateKeyPath string `mapstructure:"sign_privatekey_path"`
	SignPrivateKeyPwd  string `mapstructure:"sign_privatekey_pwd"`
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
		fmt.Println("env is empty, set default: space")
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
	User     string
	Password string
	IP       string
	Port     string
	DbName   string
}

//GetDBConfig --Get DB config from config file.
func GetDBConfig() string {
	var dbConfig DBConfig
	err := viper.UnmarshalKey("db_config", &dbConfig)
	if err != nil {
		panic(err)
	}
	mysqlURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		dbConfig.User, dbConfig.Password, dbConfig.IP, dbConfig.Port, dbConfig.DbName, "utf8")
	return mysqlURL
}

func GetBaseConf() (*BaseConf, error) {
	var baseConf BaseConf
	err := viper.UnmarshalKey("base_config", &baseConf)
	if err != nil {
		return nil, fmt.Errorf("[config] get base config failed: %s", err.Error())
	}
	return &baseConf, nil
}

func GetRootCaConf() (*CaConfig, error) {
	var rootCaConf CaConfig
	err := viper.UnmarshalKey("root_config", &rootCaConf)
	if err != nil {
		return nil, fmt.Errorf("[config] get root config failed: %s", err.Error())
	}
	return &rootCaConf, nil
}

func GetIntermediateCaConf() ([]*CaConfig, error) {
	var intermediateCaConf []*CaConfig
	err := viper.UnmarshalKey("Intermediate_config", &intermediateCaConf)
	if err != nil {
		return nil, fmt.Errorf("[config] get intermediate config failed: %s", err.Error())
	}
	return intermediateCaConf, nil
}

func GetDoubleRootPathConf() (*DoubleRootPathConf, error) {
	var doubleRootPathConf DoubleRootPathConf
	err := viper.UnmarshalKey("rootpath_double", &doubleRootPathConf)
	if err != nil {
		return nil, fmt.Errorf("[config] get double root path config failed: %s", err.Error())
	}
	return &doubleRootPathConf, nil
}

func GetAllConf() (*AllConfig, error) {
	var allConf AllConfig
	err := viper.Unmarshal(&allConf)
	if err != nil {
		return nil, fmt.Errorf("[config] get all config failed: %s", err.Error())
	}
	if allConf.baseConf == nil {
		return nil, fmt.Errorf("[config] not found base config")
	}
	if allConf.rootCaConf == nil {
		return nil, fmt.Errorf("[config] not found root config")
	}
	return &allConf, nil
}

func GetAllConfig() *AllConfig {
	return allConf
}

func (ac *AllConfig) GetHashType() string {
	return ac.baseConf.HashType
}

func (ac *AllConfig) GetKeyType() string {
	return ac.baseConf.KeyType
}

func (ac *AllConfig) GetDefaultExpireTime() int {
	return ac.baseConf.ExpireYear
}

func (ac *AllConfig) GetCanIssueCa() bool {
	return ac.baseConf.CanIssueca
}

func (ac *AllConfig) GetProvideServiceFor() []string {
	return ac.baseConf.ProvideServiceFor
}

func (ac *AllConfig) GetCaType() string {
	return ac.baseConf.CaType
}

func (ac *AllConfig) GetRootCertPath() string {
	return ac.rootCaConf.CertConf.CertPath
}
func (ac *AllConfig) GetRootKeyPath() string {
	return ac.rootCaConf.CertConf.PrivateKeyPath
}
func (ac *AllConfig) GetRootKeyPwd() string {
	return ac.rootCaConf.CertConf.PrivateKeyPwd
}

func (ac *AllConfig) GetRootConf() *CaConfig {
	return ac.rootCaConf
}
func (ac *AllConfig) GetBaseConf() *BaseConf {
	return ac.baseConf
}
func (ac *AllConfig) GetIntermediateConf() []*CaConfig {
	return ac.intermediateCaConf
}
func (ac *AllConfig) GetDoubleRootPathConf() *DoubleRootPathConf {
	return ac.doubleRootPathConf
}

func (ac *AllConfig) GetLogConf() *loggers.LogConifg {
	return ac.logConf
}
