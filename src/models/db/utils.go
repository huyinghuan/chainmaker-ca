package db

//CertType .
type UserType int

//CertStatus .
type CertStatus int

//CertUsage
type CertUsage int

const (
	ROOT_CA UserType = iota + 1
	INTERMRDIARY_CA
	USER_ADMIN
	USER_CLIENT
	NODE_CONSENSUS
	NODE_COMMON
)

const (
	ACTIVE CertStatus = iota + 1
	EXPIRED
	REVOKED
	FROZEN
)
const (
	SIGN CertUsage = iota + 1
	TLS
	TLS_SIGN
	TLS_ENC
)

//UserType2NameMap CertType to string name
var UserType2NameMap = map[UserType]string{
	ROOT_CA:         "root",
	INTERMRDIARY_CA: "ca",
	USER_ADMIN:      "admin",
	USER_CLIENT:     "client",
	NODE_CONSENSUS:  "consensus",
	NODE_COMMON:     "common",
}

//Name2UserTypeMap string name to cert type
var Name2UserTypeMap = map[string]UserType{
	"root":      ROOT_CA,
	"ca":        INTERMRDIARY_CA,
	"admin":     USER_ADMIN,
	"client":    USER_CLIENT,
	"consensus": NODE_CONSENSUS,
	"common":    NODE_COMMON,
}

//CertStatus2NameMap CertStatus to string name
var CertStatus2NameMap = map[CertStatus]string{
	ACTIVE:  "ACTIVE",
	EXPIRED: "EXPIRED",
	REVOKED: "REVOKED",
	FROZEN:  "FROZEN",
}

//Name2CertStatusMap string name to cert status
var Name2CertStatusMap = map[string]CertStatus{
	"ACTIVE":  ACTIVE,
	"EXPIRED": EXPIRED,
	"REVOKED": REVOKED,
	"FROZEN":  FROZEN,
}

//CertUsage2NameMap .
var CertUsage2NameMap = map[CertUsage]string{
	SIGN:     "sign",
	TLS:      "tls",
	TLS_SIGN: "tls-sign",
	TLS_ENC:  "tls-enc",
}

//Name2CertUsageMap .
var Name2CertUsageMap = map[string]CertUsage{
	"sign":     SIGN,
	"tls":      TLS,
	"tls-sign": TLS_SIGN,
	"tls-enc":  TLS_ENC,
}

//NodeType 节点类型
type NodeType int

const (
	COMMON_NODE NodeType = iota + 1
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

//KeyPairType
type KeyPairType struct {
	UserType  UserType
	CertUsage CertUsage
	UserId    string
	OrgId     string
}
