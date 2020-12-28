package models

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
