package db

import "chainmaker.org/chainmaker-go/common/crypto"

//CertType .
type UserType int

//CertStatus .
type CertStatus int

//CertUsage
type CertUsage int

const (
	ROOT_CA UserType = iota
	INTERMRDIARY_CA
	USER_ADMIN
	USER_USER
	NODE_CONSENSUS
	NODE_COMMON
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

//UserType2NameMap CertType to string name
var UserType2NameMap = map[UserType]string{
	ROOT_CA:         "root",
	INTERMRDIARY_CA: "ca",
	USER_ADMIN:      "admin",
	USER_USER:       "client",
	NODE_CONSENSUS:  "consensus",
	NODE_COMMON:     "common",
}

//Name2UserTypeMap string name to cert type
var Name2UserTypeMap = map[string]UserType{
	"root":      ROOT_CA,
	"ca":        INTERMRDIARY_CA,
	"admin":     USER_ADMIN,
	"client":    USER_USER,
	"consensus": NODE_CONSENSUS,
	"common":    NODE_COMMON,
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

//KeyPairUser .
type KeyPairUser struct {
	UserType  UserType
	CertUsage CertUsage
	UserID    string
	OrgID     string
}

//CertAndPrivKey .证书和对应的密钥
type CertAndPrivKey struct {
	Cert    *Cert
	PrivKey crypto.PrivateKey
	KeyPair *KeyPair
}

//GetCertResp .
type GetCertResp struct {
	CertContent []byte `json:"certContent"`
	PrivateKey  []byte `json:"privateKey"`
	Usage       string `json:"usage"`
}
