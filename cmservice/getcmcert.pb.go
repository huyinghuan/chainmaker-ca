// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        (unknown)
// source: getcmcert.proto

package cmservice

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type UserType int32

const (
	UserType_root      UserType = 0
	UserType_ca        UserType = 1
	UserType_admin     UserType = 2
	UserType_client    UserType = 3
	UserType_consensus UserType = 4
	UserType_common    UserType = 5
)

// Enum value maps for UserType.
var (
	UserType_name = map[int32]string{
		0: "root",
		1: "ca",
		2: "admin",
		3: "client",
		4: "consensus",
		5: "common",
	}
	UserType_value = map[string]int32{
		"root":      0,
		"ca":        1,
		"admin":     2,
		"client":    3,
		"consensus": 4,
		"common":    5,
	}
)

func (x UserType) Enum() *UserType {
	p := new(UserType)
	*p = x
	return p
}

func (x UserType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (UserType) Descriptor() protoreflect.EnumDescriptor {
	return file_getcmcert_proto_enumTypes[0].Descriptor()
}

func (UserType) Type() protoreflect.EnumType {
	return &file_getcmcert_proto_enumTypes[0]
}

func (x UserType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use UserType.Descriptor instead.
func (UserType) EnumDescriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{0}
}

type CertUsage int32

const (
	CertUsage_sign CertUsage = 0
	CertUsage_tls  CertUsage = 1
)

// Enum value maps for CertUsage.
var (
	CertUsage_name = map[int32]string{
		0: "sign",
		1: "tls",
	}
	CertUsage_value = map[string]int32{
		"sign": 0,
		"tls":  1,
	}
)

func (x CertUsage) Enum() *CertUsage {
	p := new(CertUsage)
	*p = x
	return p
}

func (x CertUsage) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CertUsage) Descriptor() protoreflect.EnumDescriptor {
	return file_getcmcert_proto_enumTypes[1].Descriptor()
}

func (CertUsage) Type() protoreflect.EnumType {
	return &file_getcmcert_proto_enumTypes[1]
}

func (x CertUsage) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CertUsage.Descriptor instead.
func (CertUsage) EnumDescriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{1}
}

type ChainMakerCertApplyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Orgs       []*Org `protobuf:"bytes,1,rep,name=orgs,proto3" json:"orgs,omitempty"`
	Filetarget string `protobuf:"bytes,2,opt,name=filetarget,proto3" json:"filetarget,omitempty"`
}

func (x *ChainMakerCertApplyReq) Reset() {
	*x = ChainMakerCertApplyReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChainMakerCertApplyReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChainMakerCertApplyReq) ProtoMessage() {}

func (x *ChainMakerCertApplyReq) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChainMakerCertApplyReq.ProtoReflect.Descriptor instead.
func (*ChainMakerCertApplyReq) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{0}
}

func (x *ChainMakerCertApplyReq) GetOrgs() []*Org {
	if x != nil {
		return x.Orgs
	}
	return nil
}

func (x *ChainMakerCertApplyReq) GetFiletarget() string {
	if x != nil {
		return x.Filetarget
	}
	return ""
}

type GetCertTarReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filetarget string `protobuf:"bytes,1,opt,name=filetarget,proto3" json:"filetarget,omitempty"`
	Filesource string `protobuf:"bytes,2,opt,name=filesource,proto3" json:"filesource,omitempty"`
}

func (x *GetCertTarReq) Reset() {
	*x = GetCertTarReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertTarReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertTarReq) ProtoMessage() {}

func (x *GetCertTarReq) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertTarReq.ProtoReflect.Descriptor instead.
func (*GetCertTarReq) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{1}
}

func (x *GetCertTarReq) GetFiletarget() string {
	if x != nil {
		return x.Filetarget
	}
	return ""
}

func (x *GetCertTarReq) GetFilesource() string {
	if x != nil {
		return x.Filesource
	}
	return ""
}

//无条件 string 传""
// enum 传 -1
type GetCertReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId  string    `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"` //user_name 或者 node_id
	OrgId   string    `protobuf:"bytes,2,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
	ChainId string    `protobuf:"bytes,3,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	Usage   CertUsage `protobuf:"varint,4,opt,name=usage,proto3,enum=cmservice.CertUsage" json:"usage,omitempty"`
	Type    UserType  `protobuf:"varint,5,opt,name=type,proto3,enum=cmservice.UserType" json:"type,omitempty"`
}

func (x *GetCertReq) Reset() {
	*x = GetCertReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertReq) ProtoMessage() {}

func (x *GetCertReq) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertReq.ProtoReflect.Descriptor instead.
func (*GetCertReq) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{2}
}

func (x *GetCertReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *GetCertReq) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

func (x *GetCertReq) GetChainId() string {
	if x != nil {
		return x.ChainId
	}
	return ""
}

func (x *GetCertReq) GetUsage() CertUsage {
	if x != nil {
		return x.Usage
	}
	return CertUsage_sign
}

func (x *GetCertReq) GetType() UserType {
	if x != nil {
		return x.Type
	}
	return UserType_root
}

type GetCertResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CertKey []*CertAndPrivKey `protobuf:"bytes,1,rep,name=cert_key,json=certKey,proto3" json:"cert_key,omitempty"`
}

func (x *GetCertResp) Reset() {
	*x = GetCertResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertResp) ProtoMessage() {}

func (x *GetCertResp) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertResp.ProtoReflect.Descriptor instead.
func (*GetCertResp) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{3}
}

func (x *GetCertResp) GetCertKey() []*CertAndPrivKey {
	if x != nil {
		return x.CertKey
	}
	return nil
}

type CertAndPrivKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CertContent []byte `protobuf:"bytes,1,opt,name=cert_content,json=certContent,proto3" json:"cert_content,omitempty"`
	PrivateKey  []byte `protobuf:"bytes,2,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	Usage       string `protobuf:"bytes,3,opt,name=usage,proto3" json:"usage,omitempty"`
}

func (x *CertAndPrivKey) Reset() {
	*x = CertAndPrivKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CertAndPrivKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertAndPrivKey) ProtoMessage() {}

func (x *CertAndPrivKey) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertAndPrivKey.ProtoReflect.Descriptor instead.
func (*CertAndPrivKey) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{4}
}

func (x *CertAndPrivKey) GetCertContent() []byte {
	if x != nil {
		return x.CertContent
	}
	return nil
}

func (x *CertAndPrivKey) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *CertAndPrivKey) GetUsage() string {
	if x != nil {
		return x.Usage
	}
	return ""
}

type Org struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Country  string  `protobuf:"bytes,1,opt,name=country,proto3" json:"country,omitempty"`
	Locality string  `protobuf:"bytes,2,opt,name=locality,proto3" json:"locality,omitempty"`
	Province string  `protobuf:"bytes,3,opt,name=province,proto3" json:"province,omitempty"`
	Nodes    []*Node `protobuf:"bytes,4,rep,name=nodes,proto3" json:"nodes,omitempty"`
	Users    []*User `protobuf:"bytes,5,rep,name=users,proto3" json:"users,omitempty"`
	OrgId    string  `protobuf:"bytes,6,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
}

func (x *Org) Reset() {
	*x = Org{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Org) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Org) ProtoMessage() {}

func (x *Org) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Org.ProtoReflect.Descriptor instead.
func (*Org) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{5}
}

func (x *Org) GetCountry() string {
	if x != nil {
		return x.Country
	}
	return ""
}

func (x *Org) GetLocality() string {
	if x != nil {
		return x.Locality
	}
	return ""
}

func (x *Org) GetProvince() string {
	if x != nil {
		return x.Province
	}
	return ""
}

func (x *Org) GetNodes() []*Node {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *Org) GetUsers() []*User {
	if x != nil {
		return x.Users
	}
	return nil
}

func (x *Org) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

type Node struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NodeId  string   `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	Type    UserType `protobuf:"varint,2,opt,name=type,proto3,enum=cmservice.UserType" json:"type,omitempty"`
	Sans    []string `protobuf:"bytes,3,rep,name=sans,proto3" json:"sans,omitempty"`
	ChainId string   `protobuf:"bytes,4,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{6}
}

func (x *Node) GetNodeId() string {
	if x != nil {
		return x.NodeId
	}
	return ""
}

func (x *Node) GetType() UserType {
	if x != nil {
		return x.Type
	}
	return UserType_root
}

func (x *Node) GetSans() []string {
	if x != nil {
		return x.Sans
	}
	return nil
}

func (x *Node) GetChainId() string {
	if x != nil {
		return x.ChainId
	}
	return ""
}

type User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserName string   `protobuf:"bytes,1,opt,name=user_name,json=userName,proto3" json:"user_name,omitempty"`
	Type     UserType `protobuf:"varint,2,opt,name=type,proto3,enum=cmservice.UserType" json:"type,omitempty"`
}

func (x *User) Reset() {
	*x = User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{7}
}

func (x *User) GetUserName() string {
	if x != nil {
		return x.UserName
	}
	return ""
}

func (x *User) GetType() UserType {
	if x != nil {
		return x.Type
	}
	return UserType_root
}

type TarCertResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Certfile []byte `protobuf:"bytes,1,opt,name=certfile,proto3" json:"certfile,omitempty"`
}

func (x *TarCertResp) Reset() {
	*x = TarCertResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TarCertResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TarCertResp) ProtoMessage() {}

func (x *TarCertResp) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TarCertResp.ProtoReflect.Descriptor instead.
func (*TarCertResp) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{8}
}

func (x *TarCertResp) GetCertfile() []byte {
	if x != nil {
		return x.Certfile
	}
	return nil
}

type GenerateResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filepath string `protobuf:"bytes,1,opt,name=filepath,proto3" json:"filepath,omitempty"`
}

func (x *GenerateResp) Reset() {
	*x = GenerateResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateResp) ProtoMessage() {}

func (x *GenerateResp) ProtoReflect() protoreflect.Message {
	mi := &file_getcmcert_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateResp.ProtoReflect.Descriptor instead.
func (*GenerateResp) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{9}
}

func (x *GenerateResp) GetFilepath() string {
	if x != nil {
		return x.Filepath
	}
	return ""
}

var File_getcmcert_proto protoreflect.FileDescriptor

var file_getcmcert_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x67, 0x65, 0x74, 0x63, 0x6d, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x5c, 0x0a, 0x16,
	0x43, 0x68, 0x61, 0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70,
	0x70, 0x6c, 0x79, 0x52, 0x65, 0x71, 0x12, 0x22, 0x0a, 0x04, 0x6f, 0x72, 0x67, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x4f, 0x72, 0x67, 0x52, 0x04, 0x6f, 0x72, 0x67, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x66, 0x69,
	0x6c, 0x65, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x66, 0x69, 0x6c, 0x65, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x22, 0x4f, 0x0a, 0x0d, 0x47, 0x65,
	0x74, 0x43, 0x65, 0x72, 0x74, 0x54, 0x61, 0x72, 0x52, 0x65, 0x71, 0x12, 0x1e, 0x0a, 0x0a, 0x66,
	0x69, 0x6c, 0x65, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0a, 0x66, 0x69, 0x6c, 0x65, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x66,
	0x69, 0x6c, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0a, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xac, 0x01, 0x0a, 0x0a,
	0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x49, 0x64, 0x12, 0x2a, 0x0a, 0x05, 0x75, 0x73, 0x61, 0x67, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x43, 0x65, 0x72, 0x74, 0x55, 0x73, 0x61, 0x67, 0x65, 0x52, 0x05, 0x75, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x27, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x13, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x22, 0x43, 0x0a, 0x0b, 0x47, 0x65,
	0x74, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x12, 0x34, 0x0a, 0x08, 0x63, 0x65, 0x72,
	0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x6d,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x41, 0x6e, 0x64, 0x50,
	0x72, 0x69, 0x76, 0x4b, 0x65, 0x79, 0x52, 0x07, 0x63, 0x65, 0x72, 0x74, 0x4b, 0x65, 0x79, 0x22,
	0x6a, 0x0a, 0x0e, 0x43, 0x65, 0x72, 0x74, 0x41, 0x6e, 0x64, 0x50, 0x72, 0x69, 0x76, 0x4b, 0x65,
	0x79, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x75, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x75, 0x73, 0x61, 0x67, 0x65, 0x22, 0xbc, 0x01, 0x0a, 0x03,
	0x4f, 0x72, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x1a, 0x0a,
	0x08, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x6e, 0x63, 0x65, 0x12, 0x25, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x05,
	0x75, 0x73, 0x65, 0x72, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x63, 0x6d,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x05, 0x75, 0x73,
	0x65, 0x72, 0x73, 0x12, 0x15, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x22, 0x77, 0x0a, 0x04, 0x4e, 0x6f,
	0x64, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x6e, 0x6f, 0x64, 0x65, 0x49, 0x64, 0x12, 0x27, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x63, 0x6d, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x61, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x04, 0x73, 0x61, 0x6e, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69,
	0x6e, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69,
	0x6e, 0x49, 0x64, 0x22, 0x4c, 0x0a, 0x04, 0x55, 0x73, 0x65, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x75,
	0x73, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x22, 0x29, 0x0a, 0x0b, 0x54, 0x61, 0x72, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x12, 0x1a, 0x0a, 0x08, 0x63, 0x65, 0x72, 0x74, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x08, 0x63, 0x65, 0x72, 0x74, 0x66, 0x69, 0x6c, 0x65, 0x22, 0x2a, 0x0a, 0x0c,
	0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x12, 0x1a, 0x0a, 0x08,
	0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x2a, 0x4e, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x72, 0x6f, 0x6f, 0x74, 0x10, 0x00, 0x12, 0x06,
	0x0a, 0x02, 0x63, 0x61, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x10,
	0x02, 0x12, 0x0a, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x10, 0x03, 0x12, 0x0d, 0x0a,
	0x09, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x10, 0x04, 0x12, 0x0a, 0x0a, 0x06,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x10, 0x05, 0x2a, 0x1e, 0x0a, 0x09, 0x43, 0x65, 0x72, 0x74,
	0x55, 0x73, 0x61, 0x67, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x73, 0x69, 0x67, 0x6e, 0x10, 0x00, 0x12,
	0x07, 0x0a, 0x03, 0x74, 0x6c, 0x73, 0x10, 0x01, 0x32, 0xed, 0x01, 0x0a, 0x13, 0x43, 0x68, 0x61,
	0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70, 0x70, 0x6c, 0x79,
	0x12, 0x4c, 0x0a, 0x0c, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x43, 0x65, 0x72, 0x74,
	0x12, 0x21, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x68, 0x61,
	0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70, 0x70, 0x6c, 0x79,
	0x52, 0x65, 0x71, 0x1a, 0x17, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x22, 0x00, 0x12, 0x40,
	0x0a, 0x0a, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x54, 0x61, 0x72, 0x12, 0x18, 0x2e, 0x63,
	0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74,
	0x54, 0x61, 0x72, 0x52, 0x65, 0x71, 0x1a, 0x16, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x54, 0x61, 0x72, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x22, 0x00,
	0x12, 0x46, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x42, 0x79, 0x43, 0x6f, 0x6e,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x15, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x1a, 0x16,
	0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65,
	0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x22, 0x00, 0x42, 0x0d, 0x5a, 0x0b, 0x2e, 0x3b, 0x63, 0x6d,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_getcmcert_proto_rawDescOnce sync.Once
	file_getcmcert_proto_rawDescData = file_getcmcert_proto_rawDesc
)

func file_getcmcert_proto_rawDescGZIP() []byte {
	file_getcmcert_proto_rawDescOnce.Do(func() {
		file_getcmcert_proto_rawDescData = protoimpl.X.CompressGZIP(file_getcmcert_proto_rawDescData)
	})
	return file_getcmcert_proto_rawDescData
}

var file_getcmcert_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_getcmcert_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_getcmcert_proto_goTypes = []interface{}{
	(UserType)(0),                  // 0: cmservice.UserType
	(CertUsage)(0),                 // 1: cmservice.CertUsage
	(*ChainMakerCertApplyReq)(nil), // 2: cmservice.ChainMakerCertApplyReq
	(*GetCertTarReq)(nil),          // 3: cmservice.GetCertTarReq
	(*GetCertReq)(nil),             // 4: cmservice.GetCertReq
	(*GetCertResp)(nil),            // 5: cmservice.GetCertResp
	(*CertAndPrivKey)(nil),         // 6: cmservice.CertAndPrivKey
	(*Org)(nil),                    // 7: cmservice.Org
	(*Node)(nil),                   // 8: cmservice.Node
	(*User)(nil),                   // 9: cmservice.User
	(*TarCertResp)(nil),            // 10: cmservice.TarCertResp
	(*GenerateResp)(nil),           // 11: cmservice.GenerateResp
}
var file_getcmcert_proto_depIdxs = []int32{
	7,  // 0: cmservice.ChainMakerCertApplyReq.orgs:type_name -> cmservice.Org
	1,  // 1: cmservice.GetCertReq.usage:type_name -> cmservice.CertUsage
	0,  // 2: cmservice.GetCertReq.type:type_name -> cmservice.UserType
	6,  // 3: cmservice.GetCertResp.cert_key:type_name -> cmservice.CertAndPrivKey
	8,  // 4: cmservice.Org.nodes:type_name -> cmservice.Node
	9,  // 5: cmservice.Org.users:type_name -> cmservice.User
	0,  // 6: cmservice.Node.type:type_name -> cmservice.UserType
	0,  // 7: cmservice.User.type:type_name -> cmservice.UserType
	2,  // 8: cmservice.ChainMakerCertApply.GenerateCert:input_type -> cmservice.ChainMakerCertApplyReq
	3,  // 9: cmservice.ChainMakerCertApply.GetCertTar:input_type -> cmservice.GetCertTarReq
	4,  // 10: cmservice.ChainMakerCertApply.GetCertByConditions:input_type -> cmservice.GetCertReq
	11, // 11: cmservice.ChainMakerCertApply.GenerateCert:output_type -> cmservice.GenerateResp
	10, // 12: cmservice.ChainMakerCertApply.GetCertTar:output_type -> cmservice.TarCertResp
	5,  // 13: cmservice.ChainMakerCertApply.GetCertByConditions:output_type -> cmservice.GetCertResp
	11, // [11:14] is the sub-list for method output_type
	8,  // [8:11] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_getcmcert_proto_init() }
func file_getcmcert_proto_init() {
	if File_getcmcert_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_getcmcert_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChainMakerCertApplyReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertTarReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CertAndPrivKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Org); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Node); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*User); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TarCertResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_getcmcert_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_getcmcert_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_getcmcert_proto_goTypes,
		DependencyIndexes: file_getcmcert_proto_depIdxs,
		EnumInfos:         file_getcmcert_proto_enumTypes,
		MessageInfos:      file_getcmcert_proto_msgTypes,
	}.Build()
	File_getcmcert_proto = out.File
	file_getcmcert_proto_rawDesc = nil
	file_getcmcert_proto_goTypes = nil
	file_getcmcert_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ChainMakerCertApplyClient is the client API for ChainMakerCertApply service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ChainMakerCertApplyClient interface {
	GenerateCert(ctx context.Context, in *ChainMakerCertApplyReq, opts ...grpc.CallOption) (*GenerateResp, error)
	GetCertTar(ctx context.Context, in *GetCertTarReq, opts ...grpc.CallOption) (*TarCertResp, error)
	GetCertByConditions(ctx context.Context, in *GetCertReq, opts ...grpc.CallOption) (*GetCertResp, error)
}

type chainMakerCertApplyClient struct {
	cc grpc.ClientConnInterface
}

func NewChainMakerCertApplyClient(cc grpc.ClientConnInterface) ChainMakerCertApplyClient {
	return &chainMakerCertApplyClient{cc}
}

func (c *chainMakerCertApplyClient) GenerateCert(ctx context.Context, in *ChainMakerCertApplyReq, opts ...grpc.CallOption) (*GenerateResp, error) {
	out := new(GenerateResp)
	err := c.cc.Invoke(ctx, "/cmservice.ChainMakerCertApply/GenerateCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chainMakerCertApplyClient) GetCertTar(ctx context.Context, in *GetCertTarReq, opts ...grpc.CallOption) (*TarCertResp, error) {
	out := new(TarCertResp)
	err := c.cc.Invoke(ctx, "/cmservice.ChainMakerCertApply/GetCertTar", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *chainMakerCertApplyClient) GetCertByConditions(ctx context.Context, in *GetCertReq, opts ...grpc.CallOption) (*GetCertResp, error) {
	out := new(GetCertResp)
	err := c.cc.Invoke(ctx, "/cmservice.ChainMakerCertApply/GetCertByConditions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ChainMakerCertApplyServer is the server API for ChainMakerCertApply service.
type ChainMakerCertApplyServer interface {
	GenerateCert(context.Context, *ChainMakerCertApplyReq) (*GenerateResp, error)
	GetCertTar(context.Context, *GetCertTarReq) (*TarCertResp, error)
	GetCertByConditions(context.Context, *GetCertReq) (*GetCertResp, error)
}

// UnimplementedChainMakerCertApplyServer can be embedded to have forward compatible implementations.
type UnimplementedChainMakerCertApplyServer struct {
}

func (*UnimplementedChainMakerCertApplyServer) GenerateCert(context.Context, *ChainMakerCertApplyReq) (*GenerateResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateCert not implemented")
}
func (*UnimplementedChainMakerCertApplyServer) GetCertTar(context.Context, *GetCertTarReq) (*TarCertResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertTar not implemented")
}
func (*UnimplementedChainMakerCertApplyServer) GetCertByConditions(context.Context, *GetCertReq) (*GetCertResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertByConditions not implemented")
}

func RegisterChainMakerCertApplyServer(s *grpc.Server, srv ChainMakerCertApplyServer) {
	s.RegisterService(&_ChainMakerCertApply_serviceDesc, srv)
}

func _ChainMakerCertApply_GenerateCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChainMakerCertApplyReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChainMakerCertApplyServer).GenerateCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cmservice.ChainMakerCertApply/GenerateCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChainMakerCertApplyServer).GenerateCert(ctx, req.(*ChainMakerCertApplyReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChainMakerCertApply_GetCertTar_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertTarReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChainMakerCertApplyServer).GetCertTar(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cmservice.ChainMakerCertApply/GetCertTar",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChainMakerCertApplyServer).GetCertTar(ctx, req.(*GetCertTarReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChainMakerCertApply_GetCertByConditions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChainMakerCertApplyServer).GetCertByConditions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cmservice.ChainMakerCertApply/GetCertByConditions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChainMakerCertApplyServer).GetCertByConditions(ctx, req.(*GetCertReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _ChainMakerCertApply_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cmservice.ChainMakerCertApply",
	HandlerType: (*ChainMakerCertApplyServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GenerateCert",
			Handler:    _ChainMakerCertApply_GenerateCert_Handler,
		},
		{
			MethodName: "GetCertTar",
			Handler:    _ChainMakerCertApply_GetCertTar_Handler,
		},
		{
			MethodName: "GetCertByConditions",
			Handler:    _ChainMakerCertApply_GetCertByConditions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "getcmcert.proto",
}
