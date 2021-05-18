package utils

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-go/common/crypto"
	"github.com/spf13/viper"
)

//CaConfig
type RootCaConf struct {
	Country           string `mapstructure:"country"`
	Locality          string `mapstructure:"locality"`
	Province          string `mapstructure:"province"`
	PrivateKeyPwd     string `mapstructure:"private_key_pwd"`
	OrgId             string `mapstructure:"org_id"`
	IsGenerateKeypair bool   `mapstructure:"is_generate_keypair"`
	CertPath          string `mapstructure:"cert_path"`
	PrivateKeyPath    string `mapstructure:"privatekey_path"`
}

type DoubleRootPathConf struct {
	TlsCertPath        string `mapstructure:"tls_cert_path"`
	TlsPrivateKeyPath  string `mapstructure:"tls_privatekey_path"`
	SignCertPath       string `mapstructure:"sign_cert_path"`
	SignPrivateKeyPath string `mapstructure:"sign_privatekey_path"`
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
	if err := viper.ReadInConfig(); err != nil {
		log.Println("Init config error: " + err.Error())
		return
	}
	var logConf loggers.LogConifg
	logConf.Level = viper.GetString("log_config.level")
	logConf.FileName = viper.GetString("log_config.filename")
	logConf.MaxAge = viper.GetInt("log_config.max_age")
	logConf.MaxSize = viper.GetInt("log_level.max_size")
	logConf.MaxBackups = viper.GetInt("log_max_backups")
	err := loggers.InitLogger(&logConf)
	if err != nil {
		log.Println("Init logger error: " + err.Error())
		return
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

//GetRootCaConfig Read root CA config file
func GetRootCaConfig() (*RootCaConf, error) {
	var rootCaConfig RootCaConf
	err := viper.UnmarshalKey("root_config", &rootCaConfig)
	if err != nil {
		return &rootCaConfig, fmt.Errorf("[Config] get root config error: %s", err.Error())
	}
	return &rootCaConfig, nil
}

//GetRootPathConf .
func GetRootPathConf() (*DoubleRootPathConf, error) {
	var rootPathConf DoubleRootPathConf
	err := viper.UnmarshalKey("rootpath_double", &rootPathConf)
	if err != nil {
		return &rootPathConf, fmt.Errorf("[Config] get double root ca path conf error: %s", err.Error())
	}
	return &rootPathConf, nil
}
func GetHashType(inputHashType string) (crypto.HashType, error) {
	if inputHashType != "" || len(inputHashType) != 0 {
		hashType, ok := Name2HashTypeMap[inputHashType]
		if !ok {
			return 0, fmt.Errorf("[get hash type] this hash type is not support,[%s]", inputHashType)
		}
		return hashType, nil
	}
	confHashType := viper.GetString("hash_type")
	hashType, ok := Name2HashTypeMap[confHashType]
	if !ok {
		return 0, fmt.Errorf("[get hash type] hash type in config is not support,[%s]", confHashType)
	}
	return hashType, nil
}

func GetPrivateKeyType(inputKeyType string) (crypto.KeyType, error) {
	if inputKeyType != "" || len(inputKeyType) != 0 {
		keyType, ok := crypto.Name2KeyTypeMap[inputKeyType]
		if !ok {
			return 0, fmt.Errorf("[get hash type] this key type is not support,[%s]", inputKeyType)
		}
		return keyType, nil
	}
	confKeyType := viper.GetString("key_type")
	keyType, ok := crypto.Name2KeyTypeMap[confKeyType]
	if !ok {
		return 0, fmt.Errorf("[get hash type] key type in config is not support,[%s]", confKeyType)
	}
	return keyType, nil
}

func IsGenerateRootCA() bool {
	return viper.GetBool("is_generate_rootca")
}

func GetCaType() string {
	return viper.GetString("ca_type")
}

func GetDefaultExpireTime() int32 {
	return viper.GetInt32("expire_year")
}

func GetDefaultHashType() string {
	return viper.GetString("hash_type")
}

func GetDefaultKeyType() string {
	return viper.GetString("key_type")
}

func GetCRLNextTime() time.Duration {
	d, err := time.ParseDuration(viper.GetString("crl_next_time"))
	if err != nil {
		return time.Hour * 24
	}
	return d
}
