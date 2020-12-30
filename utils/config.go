package utils

import (
	"fmt"
	"log"

	"chainmaker.org/wx-CRA-backend/loggers"
	"github.com/spf13/viper"
)

//Config .
type Config struct {
	LogConfig loggers.LogConifg
	DBConfig  DBConfig
}

//CaConfig 根配置
type CaConfig struct {
	PrivateKeyType     string `mapstructure:"private_key_type"`
	PrivateKeyPath     string `mapstructure:"private_key_path"`
	PrivateKeyName     string `mapstructure:"private_key_name"`
	CertName           string `mapstructure:"cert_name"`
	CertPath           string `mapstructure:"cert_path"`
	HashType           string `mapstructure:"hash_type"`
	ExpireYear         int32  `mapstructure:"expire_year"`
	Country            string `mapstructure:"country"`
	Locality           string `mapstructure:"locality"`
	Province           string `mapstructure:"province"`
	OrganizationalUnit string `mapstructure:"OU"`
	Organization       string `mapstructure:"O"`
	CommonName         string `mapstructure:"CN"`
	CsrPath            string `mapstructure:"csr_path"`
	CsrName            string `mapstructure:"csr_name"`
}

//InitConfig .
func InitConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./conf")

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
		return rootCaConfig, err
	}
	return rootCaConfig, nil
}
