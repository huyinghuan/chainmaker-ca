package models

//Cert 证书
type Cert struct {
	ID                 int    `gorm:"primary_key;AUTO_INCREMENT"`
	Name               string `gorm:"unique_index:cert_name_index"`
	PrivateKeyType     string
	Content            []byte
	HashTyep           string
	ExpireYear         int32
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	CsrContent         []byte
}
