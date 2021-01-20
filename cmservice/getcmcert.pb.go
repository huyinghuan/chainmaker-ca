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
	UserType_admin  UserType = 0
	UserType_client UserType = 1
)

// Enum value maps for UserType.
var (
	UserType_name = map[int32]string{
		0: "admin",
		1: "client",
	}
	UserType_value = map[string]int32{
		"admin":  0,
		"client": 1,
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

type NodeType int32

const (
	NodeType_consensus NodeType = 0
	NodeType_common    NodeType = 1
)

// Enum value maps for NodeType.
var (
	NodeType_name = map[int32]string{
		0: "consensus",
		1: "common",
	}
	NodeType_value = map[string]int32{
		"consensus": 0,
		"common":    1,
	}
)

func (x NodeType) Enum() *NodeType {
	p := new(NodeType)
	*p = x
	return p
}

func (x NodeType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NodeType) Descriptor() protoreflect.EnumDescriptor {
	return file_getcmcert_proto_enumTypes[1].Descriptor()
}

func (NodeType) Type() protoreflect.EnumType {
	return &file_getcmcert_proto_enumTypes[1]
}

func (x NodeType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NodeType.Descriptor instead.
func (NodeType) EnumDescriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{1}
}

type ChainMakerCertApplyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChainId    string `protobuf:"bytes,1,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	Orgs       []*Org `protobuf:"bytes,2,rep,name=orgs,proto3" json:"orgs,omitempty"`
	Filetarget string `protobuf:"bytes,3,opt,name=filetarget,proto3" json:"filetarget,omitempty"`
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

func (x *ChainMakerCertApplyReq) GetChainId() string {
	if x != nil {
		return x.ChainId
	}
	return ""
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
		mi := &file_getcmcert_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Org) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Org) ProtoMessage() {}

func (x *Org) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Org.ProtoReflect.Descriptor instead.
func (*Org) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{2}
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

	NodeId string   `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	Type   NodeType `protobuf:"varint,2,opt,name=type,proto3,enum=cmservice.NodeType" json:"type,omitempty"`
	Sans   []string `protobuf:"bytes,3,rep,name=sans,proto3" json:"sans,omitempty"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_getcmcert_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{3}
}

func (x *Node) GetNodeId() string {
	if x != nil {
		return x.NodeId
	}
	return ""
}

func (x *Node) GetType() NodeType {
	if x != nil {
		return x.Type
	}
	return NodeType_consensus
}

func (x *Node) GetSans() []string {
	if x != nil {
		return x.Sans
	}
	return nil
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
		mi := &file_getcmcert_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{4}
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
	return UserType_admin
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
		mi := &file_getcmcert_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TarCertResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TarCertResp) ProtoMessage() {}

func (x *TarCertResp) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use TarCertResp.ProtoReflect.Descriptor instead.
func (*TarCertResp) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{5}
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
		mi := &file_getcmcert_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateResp) ProtoMessage() {}

func (x *GenerateResp) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use GenerateResp.ProtoReflect.Descriptor instead.
func (*GenerateResp) Descriptor() ([]byte, []int) {
	return file_getcmcert_proto_rawDescGZIP(), []int{6}
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
	0x6f, 0x12, 0x09, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x77, 0x0a, 0x16,
	0x43, 0x68, 0x61, 0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70,
	0x70, 0x6c, 0x79, 0x52, 0x65, 0x71, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49,
	0x64, 0x12, 0x22, 0x0a, 0x04, 0x6f, 0x72, 0x67, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x0e, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x4f, 0x72, 0x67, 0x52,
	0x04, 0x6f, 0x72, 0x67, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x22, 0x4f, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74,
	0x54, 0x61, 0x72, 0x52, 0x65, 0x71, 0x12, 0x1e, 0x0a, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x66, 0x69, 0x6c, 0x65,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x66, 0x69, 0x6c, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xbc, 0x01, 0x0a, 0x03, 0x4f, 0x72, 0x67, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x6f, 0x63, 0x61,
	0x6c, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61,
	0x6c, 0x69, 0x74, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x6e, 0x63, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x6e, 0x63, 0x65,
	0x12, 0x25, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x4e, 0x6f, 0x64, 0x65,
	0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73,
	0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73, 0x12, 0x15,
	0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x6f, 0x72, 0x67, 0x49, 0x64, 0x22, 0x5c, 0x0a, 0x04, 0x4e, 0x6f, 0x64, 0x65, 0x12, 0x17, 0x0a,
	0x07, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x6e, 0x6f, 0x64, 0x65, 0x49, 0x64, 0x12, 0x27, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x73, 0x61, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x73,
	0x61, 0x6e, 0x73, 0x22, 0x4c, 0x0a, 0x04, 0x55, 0x73, 0x65, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x75,
	0x73, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x22, 0x29, 0x0a, 0x0b, 0x54, 0x61, 0x72, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x12, 0x1a, 0x0a, 0x08, 0x63, 0x65, 0x72, 0x74, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x08, 0x63, 0x65, 0x72, 0x74, 0x66, 0x69, 0x6c, 0x65, 0x22, 0x2a, 0x0a, 0x0c,
	0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x12, 0x1a, 0x0a, 0x08,
	0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x66, 0x69, 0x6c, 0x65, 0x70, 0x61, 0x74, 0x68, 0x2a, 0x21, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x09, 0x0a, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x10, 0x00, 0x12,
	0x0a, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x10, 0x01, 0x2a, 0x25, 0x0a, 0x08, 0x4e,
	0x6f, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x73, 0x65,
	0x6e, 0x73, 0x75, 0x73, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x10, 0x01, 0x32, 0xa5, 0x01, 0x0a, 0x13, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65,
	0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70, 0x70, 0x6c, 0x79, 0x12, 0x4c, 0x0a, 0x0c, 0x47, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x43, 0x65, 0x72, 0x74, 0x12, 0x21, 0x2e, 0x63, 0x6d, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x4d, 0x61, 0x6b, 0x65,
	0x72, 0x43, 0x65, 0x72, 0x74, 0x41, 0x70, 0x70, 0x6c, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x17, 0x2e,
	0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x22, 0x00, 0x12, 0x40, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x43,
	0x65, 0x72, 0x74, 0x54, 0x61, 0x72, 0x12, 0x18, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x54, 0x61, 0x72, 0x52, 0x65, 0x71,
	0x1a, 0x16, 0x2e, 0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x54, 0x61, 0x72,
	0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x22, 0x00, 0x42, 0x0d, 0x5a, 0x0b, 0x2e, 0x3b,
	0x63, 0x6d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
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
var file_getcmcert_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_getcmcert_proto_goTypes = []interface{}{
	(UserType)(0),                  // 0: cmservice.UserType
	(NodeType)(0),                  // 1: cmservice.NodeType
	(*ChainMakerCertApplyReq)(nil), // 2: cmservice.ChainMakerCertApplyReq
	(*GetCertTarReq)(nil),          // 3: cmservice.GetCertTarReq
	(*Org)(nil),                    // 4: cmservice.Org
	(*Node)(nil),                   // 5: cmservice.Node
	(*User)(nil),                   // 6: cmservice.User
	(*TarCertResp)(nil),            // 7: cmservice.TarCertResp
	(*GenerateResp)(nil),           // 8: cmservice.GenerateResp
}
var file_getcmcert_proto_depIdxs = []int32{
	4, // 0: cmservice.ChainMakerCertApplyReq.orgs:type_name -> cmservice.Org
	5, // 1: cmservice.Org.nodes:type_name -> cmservice.Node
	6, // 2: cmservice.Org.users:type_name -> cmservice.User
	1, // 3: cmservice.Node.type:type_name -> cmservice.NodeType
	0, // 4: cmservice.User.type:type_name -> cmservice.UserType
	2, // 5: cmservice.ChainMakerCertApply.GenerateCert:input_type -> cmservice.ChainMakerCertApplyReq
	3, // 6: cmservice.ChainMakerCertApply.GetCertTar:input_type -> cmservice.GetCertTarReq
	8, // 7: cmservice.ChainMakerCertApply.GenerateCert:output_type -> cmservice.GenerateResp
	7, // 8: cmservice.ChainMakerCertApply.GetCertTar:output_type -> cmservice.TarCertResp
	7, // [7:9] is the sub-list for method output_type
	5, // [5:7] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
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
		file_getcmcert_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
		file_getcmcert_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
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
		file_getcmcert_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
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
		file_getcmcert_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
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
			NumMessages:   7,
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

// ChainMakerCertApplyServer is the server API for ChainMakerCertApply service.
type ChainMakerCertApplyServer interface {
	GenerateCert(context.Context, *ChainMakerCertApplyReq) (*GenerateResp, error)
	GetCertTar(context.Context, *GetCertTarReq) (*TarCertResp, error)
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
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "getcmcert.proto",
}
