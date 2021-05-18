package db

import (
	"chainmaker.org/chainmaker-go/common/crypto"
)

const (
	CERT_CONTENT_NAME = "cert_content"
	CERT_INFO_NAME    = "cert_info"
	KEY_PAIR_NAME     = "key_pair"
	REVOKED_CERT_NAME = "revoked_cert"
)

type TableModel struct {
	Id        int `gorm:"primaryKey;autoIncrement"`
	CreatedAt int
	UpdatedAt int
}

//CertContent The initiatively populated field in the program & the final generated certificate file
type CertContent struct {
	TableModel
	SerialNumber       int64  `gorm:"uniqueIndex"`
	Content            string `gorm:"type:longtext"`
	Signature          string `gorm:"type:longtext"`
	CertRow            string `gorm:"type:longtext"`
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	Ski                string
	Aki                string
	KeyUsage           int
	ExtKeyUsage        string
	CsrContent         string `gorm:"type:longtext"`
	IsCa               bool
	IssueDate          int64
	InvalidDate        int64
}

//CertInfo Other relevant information
type CertInfo struct {
	TableModel
	SerialNumber int64
	PrivateKeyId string
	CertStatus   CertStatus
	IssuerSn     int64
	P2pNodeId    string
	UserType     UserType  `gorm:"uniqueIndex:usertype_certusage_userid_orgid_index"`
	CertUsage    CertUsage `gorm:"uniqueIndex:usertype_certusage_userid_orgid_index"`
	UserId       string    `gorm:"uniqueIndex:usertype_certusage_userid_orgid_index"`
	OrgId        string    `gorm:"uniqueIndex:usertype_certusage_userid_orgid_index"`
}

//KeyPair public/private key pair informations
type KeyPair struct {
	TableModel
	Ski           string `gorm:"uniqueIndex"`
	PrivateKey    string `gorm:"type:longtext"`
	PublicKey     string `gorm:"type:longtext"`
	PrivateKeyPwd string
	HashType      crypto.HashType
	KeyType       crypto.KeyType
}

//RevokedCert revoked cert
type RevokedCert struct {
	TableModel
	RevokedCertSN    int64
	Reason           string
	RevokedStartTime int64
	RevokedEndTime   int64
	RevokedBy        int64
}

func (*CertContent) TableName() string {
	return CERT_CONTENT_NAME
}
func (*CertInfo) TableName() string {
	return CERT_INFO_NAME
}
func (*KeyPair) TableName() string {
	return KEY_PAIR_NAME
}
func (*RevokedCert) TableName() string {
	return REVOKED_CERT_NAME
}
