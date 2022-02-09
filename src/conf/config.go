package conf

import (
	"embed"
	"fmt"
	"log"
	"os"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

var allConf *AllConfig
var logger *zap.Logger

type AllConfig struct {
	LogConf             *loggers.LogConifg   `yaml:"log_config"`
	DBConf              *DBConfig            `yaml:"db_config"`
	BaseConf            *BaseConf            `yaml:"base_config"`
	RootCaConf          *CaConfig            `yaml:"root_config"`
	IntermediateCaConfs []*ImCaConfig        `yaml:"intermediate_config"`
	AccessControlConfs  []*AccessControlConf `yaml:"access_control_config"`
}

type BaseConf struct {
	ServerPort        string   `yaml:"server_port"`
	CaType            string   `yaml:"ca_type"`
	ExpireYear        int      `yaml:"expire_year"`
	HashType          string   `yaml:"hash_type"`
	KeyType           string   `yaml:"key_type"`
	CanIssueca        bool     `yaml:"can_issue_ca"`
	ProvideServiceFor []string `yaml:"provide_service_for"`
	IsKeyEncrypt      bool     `yaml:"key_encrypt"`
	AccessControl     bool     `yaml:"access_control"`
}

type CaConfig struct {
	CsrConf  *CsrConf    `yaml:"csr"`
	CertConf []*CertConf `yaml:"cert"`
}

type ImCaConfig struct {
	CsrConf       *CsrConf `yaml:"csr"`
	PrivateKeyPwd string   `yaml:"private_key_pwd"`
}

type CsrConf struct {
	CN       string `yaml:"CN"`
	O        string `yaml:"O"`
	OU       string `yaml:"OU"`
	Country  string `yaml:"country"`
	Locality string `yaml:"locality"`
	Province string `yaml:"province"`
}

type CertConf struct {
	CertType       string `yaml:"cert_type"`
	CertPath       string `yaml:"cert_path"`
	PrivateKeyPath string `yaml:"private_key_path"`
}

type AccessControlConf struct {
	AppRole string `yaml:"app_role"`
	AppId   string `yaml:"app_id"`
	AppKey  string `yaml:"app_key"`
}

var RunMode = ""

//go:embed asserts
var configFiles embed.FS

func ReadFile(filepath string) ([]byte, error) {
	return configFiles.ReadFile(filepath)
}

func init() {
	runmode := os.Getenv("RUN_MODE")
	if runmode == "" {
		runmode = RunMode
	}
	configPath := "asserts/config.dev.yaml"
	if runmode == "product" {
		configPath = "asserts/config.yaml"
	}
	log.Println("当前配置:", configPath)
	body, err := configFiles.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	var f AllConfig
	err = yaml.Unmarshal(body, &f)
	if err != nil {
		panic(err)
	}
	allConf = &f
	if err := checkAllConf(); err != nil {
		panic(err)
	}
	err = loggers.InitLogger(allConf.GetLogConf())
	if err != nil {
		panic(err)
	}
	logger = loggers.GetLogger()
	logger.Info("init config successful", zap.Any("allconfig", allConf))
}

//DBConfig /
type DBConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	IP       string `yaml:"ip"`
	Port     string `yaml:"port"`
	DbName   string `yaml:"dbname"`
}

//GetDBConfig --Get DB config from config file.
func GetDBConfig() string {
	dbConfig := allConf.GetDBConf()
	mysqlURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		dbConfig.User, dbConfig.Password, dbConfig.IP, dbConfig.Port, dbConfig.DbName, "utf8")
	return mysqlURL
}

//Get all conf
func checkAllConf() error {

	if allConf.DBConf == nil {
		return fmt.Errorf("get all config failed: not found db config")
	}
	if allConf.BaseConf == nil {
		return fmt.Errorf("get all config failed: not found base config")
	}
	if allConf.RootCaConf == nil {
		return fmt.Errorf("get all config failed: not found root config")
	}
	return nil
}

func GetAllConfig() *AllConfig {
	return allConf
}

func (ac *AllConfig) GetServerPort() string {
	return ac.BaseConf.ServerPort
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

func (ac *AllConfig) IsAccessControl() bool {
	return ac.BaseConf.AccessControl
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
	return ac.IntermediateCaConfs
}

func (ac *AllConfig) GetLogConf() *loggers.LogConifg {
	return ac.LogConf
}

func (ac *AllConfig) GetDBConf() *DBConfig {
	return ac.DBConf
}

func (ac *AllConfig) GetAccessControlConf() []*AccessControlConf {
	return ac.AccessControlConfs
}
