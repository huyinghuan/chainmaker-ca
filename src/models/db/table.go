package db

import (
	"chainmaker.org/chainmaker-go/common/crypto"
)

//Cert Cert Informations
type Cert struct {
	Id                 int    `gorm:"primary_key;AUTO_INCREMENT"` //id
	SerialNumber       int64  `gorm:"unique_index:cert_sn_index"` //cert sn
	Content            []byte `gorm:"type:mediumblob"`            //cert content
	Signature          string `gorm:"type:longtext"`              //cert signature
	CertEncode         string `gorm:"type:longtext"`              //cert encode
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	CsrContent         []byte     `gorm:"type:mediumblob"` //cert csr
	CertStatus         CertStatus //cert status
	IsCa               bool       //is issue ability
	IssueDate          int64      //issue date
	InvalidDate        int64      //invalid date
	PrivateKeyId       string     //private id
	IssuerSn           int64      //issuer sn
	NodeId             string     //p2p net work id
}

//TableName cert
func (table *Cert) TableName() string {
	return "cert"
}

//KeyPair public/private key pair informations
type KeyPair struct {
	Id            string `gorm:"primary_key"`
	PrivateKey    []byte `gorm:"type:mediumblob"`
	PublicKey     []byte `gorm:"type:mediumblob"`
	PrivateKeyPwd string
	HashType      crypto.HashType
	KeyType       crypto.KeyType
	UserType      UserType  `gorm:"unique_index:chain_org_user_usage_type_index"`
	CertUsage     CertUsage `gorm:"unique_index:chain_org_user_usage_type_index"`
	UserId        string    `gorm:"unique_index:chain_org_user_usage_type_index"`
	OrgId         string    `gorm:"unique_index:chain_org_user_usage_type_index"`
}

//TableName cert
func (table *KeyPair) TableName() string {
	return "key_pair"
}

//RevokedCert revoked cert
type RevokedCert struct {
	Id               int `gorm:"primary_key;AUTO_INCREMENT"`
	RevokedCertSN    int64
	Reason           string `gorm:"type:longtext"`
	RevokedStartTime int64
	RevokedEndTime   int64
	OrgId            string
	CertUsage        CertUsage
	CaType           UserType
}

//TableName cert
func (table *RevokedCert) TableName() string {
	return "revoked_cert"
}
