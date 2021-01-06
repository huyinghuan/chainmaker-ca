package db

import "chainmaker.org/chainmaker-go/common/crypto"

//Cert 证书信息表
type Cert struct {
	ID                 int             `gorm:"primary_key;AUTO_INCREMENT"`
	SerialNumber       int64           `gorm:"unique_index:cert_sn_index"` //证书sn
	Content            []byte          `gorm:"type:mediumblob"`            //证书内容
	Signature          string          `gorm:"type:longtext"`              //证书签名
	CertEncode         string          `gorm:"type:longtext"`              //证书编码前内容
	HashTyep           crypto.HashType //哈希类型
	ExpireYear         int32           //证书有效期
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	CsrContent         []byte   `gorm:"type:mediumblob"` //证书csr
	CertType           CertType //证书类型
	CustomerID         int      //所属用户id
	//CertStatus         CertStatus //证书状态
	IssueDate   int64 //签发日期unix
	InvalidDate int64 //到期时间unix
}

//TableName cert
func (table *Cert) TableName() string {
	return "cert"
}

//Customer 用户或者客户表
type Customer struct {
	ID       int    `gorm:"primary_key;AUTO_INCREMENT"`
	Name     string `gorm:"UNIQUE_INDEX:customer_name_index"`
	Password string
}

//TableName cert
func (table *Customer) TableName() string {
	return "customer"
}

//KeyPair 公私钥
type KeyPair struct {
	ID            int    `gorm:"primary_key;AUTO_INCREMENT"`
	PrivateKey    []byte `gorm:"type:mediumblob"`
	PublicKey     []byte `gorm:"type:mediumblob"`
	PrivateKeyPwd string //用户加密私钥所用密码
	KeyType       crypto.KeyType
	UserID        int
}

//TableName cert
func (table *KeyPair) TableName() string {
	return "key_pair"
}
