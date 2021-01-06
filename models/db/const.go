package db

//CertType .
type CertType int

//CertStatus .
type CertStatus int

const (
	ROOT_CA CertType = iota
	INTERMRDIARY_CA
	CUSTOMER
)

const (
	EFFECTIVE CertStatus = iota
	EXPIRED
	REVOKED
)

//CertType2NameMap CertType to string name
var CertType2NameMap = map[CertType]string{
	ROOT_CA:         "ROOT_CA",
	INTERMRDIARY_CA: "INTERMRDIARY_CA",
	CUSTOMER:        "CUSTOMER",
}

//Name2CertTypeMap string name to cert type
var Name2CertTypeMap = map[string]CertType{
	"ROOT_CA":         ROOT_CA,
	"INTERMRDIARY_CA": INTERMRDIARY_CA,
	"CUSTOMER":        CUSTOMER,
}

//CertStatus2NameMap CertStatus to string name
var CertStatus2NameMap = map[CertStatus]string{
	EFFECTIVE: "EFFECTIVE",
	EXPIRED:   "EXPIRED",
	REVOKED:   "REVOKED",
}

//Name2CertStatusMap string name to cert status
var Name2CertStatusMap = map[string]CertStatus{
	"EFFECTIVE": EFFECTIVE,
	"EXPIRED":   EXPIRED,
	"REVOKED":   REVOKED,
}
