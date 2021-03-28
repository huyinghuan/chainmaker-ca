package utils

import (
	"flag"
	"fmt"
	"log"
	"os"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"github.com/spf13/viper"
)

//CaConfig 根和中间Ca配置
type CaConfig struct {
	PrivateKeyPath string `mapstructure:"private_key_path"`
	CertPath       string `mapstructure:"cert_path"`
	ExpireYear     int32  `mapstructure:"expire_year"`
	Country        string `mapstructure:"country"`
	Locality       string `mapstructure:"locality"`
	Province       string `mapstructure:"province"`
	PrivateKeyPwd  string `mapstructure:"private_key_pwd"`
	OrgID          string `mapstructure:"org_id"`
	PrivateKeyType string `json:"privateKeyType"`
	HashType       string `json:"hashType"`
}

// GetConfigEnv - 获取配置环境
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

//GetFlagPath .
func GetFlagPath() string {
	var configPath string
	flag.StringVar(&configPath, "config", "./conf/config.yaml", "please input config file path")
	flag.Parse()
	return configPath
}

//SetConfig .
func SetConfig(envPath string) {
	var configPath string
	if envPath != "" {
		configPath = envPath
	} else {
		configPath = GetFlagPath()
	}
	InitConfig(configPath)
}

//InitConfig .
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

//GetDBConfig 拿到数据库配置
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

//GetRootCaConfig 读取配置文件
func GetRootCaConfig() (CaConfig, error) {
	var rootCaConfig CaConfig
	err := viper.UnmarshalKey("root_config", &rootCaConfig)
	if err != nil {
		return rootCaConfig, fmt.Errorf("[Config] get root config error: %s", err.Error())
	}
	return rootCaConfig, nil
}

//GetIntermediate 读取中间CA配置文件
func GetIntermediate() (CaConfig, error) {
	var inmediaCaConfig CaConfig
	err := viper.UnmarshalKey("Intermediate_config", &inmediaCaConfig)
	if err != nil {
		return inmediaCaConfig, fmt.Errorf("[Config] get intermediate config error: %s", err.Error())
	}
	return inmediaCaConfig, nil
}

//GetRootPrivateKey 获取根CA私钥
func GetRootPrivateKey() (privKeyFilePath, certFilePath string) {
	privKeyFilePath = viper.GetString("root_config.private_key_path")
	certFilePath = viper.GetString("root_config.cert_path")
	return
}

//GetRootPrivateKey 获取根CA私钥
func GetRootCertAndKey() (privKeyFilePath, certFilePath string) {
	keyType := GetPrivKeyType()
	hashType := GetHashType()
	privKeyFilePath = viper.GetString("root_config.private_key_path") + "root-" + keyType + ".key"
	certFilePath = viper.GetString("root_config.cert_path") + "root-" + hashType + ".crt"
	return
}

//GetRootCaPrivateKeyPwd 获取RootCa私钥密码
func GetRootCaPrivateKeyPwd() string {
	return viper.GetString("root_config.private_key_pwd")
}

//GetInitType 获取配置文件中需不需要init root ca
func GetInitType() bool {
	return viper.GetViper().GetBool("is_init_root_ca")
}

//GetPrivKeyType .
func GetPrivKeyType() string {
	return viper.GetString("private_key_type")
}

//GetHashType .
func GetHashType() string {
	return viper.GetString("hash_type")
}

//GetIssureExpirationTime .
func GetIssureExpirationTime() int32 {
	return viper.GetInt32("issure_expiration_time")
}

//GetIntermediatePrkCert .
func GetIntermediatePrkCert() (privateKeyPath, certPath string) {
	return viper.GetString("Intermediate_config.private_key_path"),
		viper.GetString("Intermediate_config.cert_path")
}

//GetIntermCAPrivateKeyPwd 获取RootCa私钥密码
func GetIntermCAPrivateKeyPwd() string {
	return viper.GetString("Intermediate_config.private_key_pwd")
}

//GetCRLNextTime .
func GetCRLNextTime() int {
	return viper.GetInt("crl_next_time")
}

//GetChainMakerCertPath .
func GetChainMakerCertPath() string {
	return viper.GetString("chainmaker_cert_path")
}

//GetChainMakerCertRPCServerPort .
func GetChainMakerCertRPCServerPort() string {
	return ":" + viper.GetString("chainmaker_cert_rpc_port")
}

//GetGenerateKeyPairType .
func GetGenerateKeyPairType() bool {
	return viper.GetBool("is_kms_keypair")
}

type KmsConfig struct {
	KmsServer string `mapstructure:"kms_server"`
	KmsRegion string `mapstructure:"kms_region"`
	SecretID  string `mapstructure:"secret_id"`
	SecretKey string `mapstructure:"secret_key"`
}

//GetKmsClientConfig 读取中间CA配置文件
func GetKmsClientConfig() (*KmsConfig, error) {
	var kmsConfig KmsConfig
	err := viper.UnmarshalKey("kms_config", &kmsConfig)
	if err != nil {
		return nil, fmt.Errorf("[Config] get kms client config error: %s", err.Error())
	}
	return &kmsConfig, nil
}

// CheckPathExist 判断文件夹是否存在
func CheckPathExist(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
