package db

//Cert 证书信息表
type Cert struct {
	ID                 int    `gorm:"primary_key;AUTO_INCREMENT"`
	SerialNumber       int64  `gorm:"unique_index:cert_sn_index"`
	Content            []byte `gorm:"type:mediumblob"`
	Signature          []byte `gorm:"type:mediumblob"`
	CertEncode         []byte `gorm:"type:mediumblob"`
	HashTyep           string
	ExpireYear         int32
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	CsrContent         []byte `gorm:"type:mediumblob"`
	CaType             string
	CustomerID         int
}

//TableName cert
func (table *Cert) TableName() string {
	return "cert"
}

//Customer 用户或者客户表
type Customer struct {
	ID            int    `gorm:"primary_key;AUTO_INCREMENT"`
	Name          string `gorm:"UNIQUE_INDEX:customer_name_index"`
	Password      string
	PrivateKey    []byte `gorm:"type:mediumblob"`
	PublicKey     []byte `gorm:"type:mediumblob"`
	PrivateKeyPwd string //用户加密私钥所用密码
	CustomerType  string //账户类型
}

//TableName cert
func (table *Customer) TableName() string {
	return "customer"
}
