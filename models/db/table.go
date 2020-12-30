package db

//Cert 证书
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
}

//TableName cert
func (table *Cert) TableName() string {
	return "cert"
}
