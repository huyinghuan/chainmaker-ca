package db

//Cert 证书
type Cert struct {
	ID                 int    `gorm:"primary_key;AUTO_INCREMENT"`
	Name               string `gorm:"unique_index:cert_name_index"`
	Content            []byte `gorm:"type:mediumblob"`
	HashTyep           string
	ExpireYear         int32
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	CsrContent         []byte `gorm:"type:mediumblob"`
}

//TableName cert
func (table *Cert) TableName() string {
	return "cert"
}
