package db

//CertType .
type CertType int

//CertStatus .
type CertStatus int

//CertUsage
type CertUsage int

const (
	ROOT_CA CertType = iota
	INTERMRDIARY_CA
	CUSTOMER_ADMIN
	CUSTOMER_USER
	NODE
)

const (
	EFFECTIVE CertStatus = iota
	EXPIRED
	REVOKED
)
const (
	SIGN CertUsage = iota
	TLS
)

//CertType2NameMap CertType to string name
var CertType2NameMap = map[CertType]string{
	ROOT_CA:         "ROOT_CA",
	INTERMRDIARY_CA: "INTERMRDIARY_CA",
	CUSTOMER_ADMIN:  "CUSTOMER_ADMIN",
	CUSTOMER_USER:   "CUSTOMER_USER",
	NODE:            "NODE",
}

//Name2CertTypeMap string name to cert type
var Name2CertTypeMap = map[string]CertType{
	"ROOT_CA":         ROOT_CA,
	"INTERMRDIARY_CA": INTERMRDIARY_CA,
	"CUSTOMER_ADMIN":  CUSTOMER_ADMIN,
	"CUSTOMER_USER":   CUSTOMER_USER,
	"NODE":            NODE,
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

//CertUsage2NameMap .
var CertUsage2NameMap = map[CertUsage]string{
	SIGN: "sign",
	TLS:  "tls",
}

//Name2CertUsageMap .
var Name2CertUsageMap = map[string]CertUsage{
	"sign": SIGN,
	"tls":  TLS,
}

//NodeType 节点类型
type NodeType int

const (
	COMMON_NODE NodeType = iota
	CONSENSUS_NODE
)

//NodeType2NameMap .
var NodeType2NameMap = map[NodeType]string{
	COMMON_NODE:    "COMMON_NODE",
	CONSENSUS_NODE: "CONSENSUS_NODE",
}

//Name2NodeTypeMap .
var Name2NodeTypeMap = map[string]NodeType{
	"COMMON_NODE":    COMMON_NODE,
	"CONSENSUS_NODE": CONSENSUS_NODE,
}
