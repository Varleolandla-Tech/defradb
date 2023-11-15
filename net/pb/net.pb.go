// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.12.4
// source: net.proto

package net_pb

import (
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

// Log represents a thread log.
type Document struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the document.
	DocKey []byte `protobuf:"bytes,1,opt,name=docKey,proto3" json:"docKey,omitempty"`
	// head of the log.
	Head []byte `protobuf:"bytes,4,opt,name=head,proto3" json:"head,omitempty"`
}

func (x *Document) Reset() {
	*x = Document{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Document) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Document) ProtoMessage() {}

func (x *Document) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Document.ProtoReflect.Descriptor instead.
func (*Document) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{0}
}

func (x *Document) GetDocKey() []byte {
	if x != nil {
		return x.DocKey
	}
	return nil
}

func (x *Document) GetHead() []byte {
	if x != nil {
		return x.Head
	}
	return nil
}

type GetDocGraphRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetDocGraphRequest) Reset() {
	*x = GetDocGraphRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetDocGraphRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetDocGraphRequest) ProtoMessage() {}

func (x *GetDocGraphRequest) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetDocGraphRequest.ProtoReflect.Descriptor instead.
func (*GetDocGraphRequest) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{1}
}

type GetDocGraphReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetDocGraphReply) Reset() {
	*x = GetDocGraphReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetDocGraphReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetDocGraphReply) ProtoMessage() {}

func (x *GetDocGraphReply) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetDocGraphReply.ProtoReflect.Descriptor instead.
func (*GetDocGraphReply) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{2}
}

type PushDocGraphRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PushDocGraphRequest) Reset() {
	*x = PushDocGraphRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushDocGraphRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushDocGraphRequest) ProtoMessage() {}

func (x *PushDocGraphRequest) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushDocGraphRequest.ProtoReflect.Descriptor instead.
func (*PushDocGraphRequest) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{3}
}

type PushDocGraphReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PushDocGraphReply) Reset() {
	*x = PushDocGraphReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushDocGraphReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushDocGraphReply) ProtoMessage() {}

func (x *PushDocGraphReply) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushDocGraphReply.ProtoReflect.Descriptor instead.
func (*PushDocGraphReply) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{4}
}

type GetLogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetLogRequest) Reset() {
	*x = GetLogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetLogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLogRequest) ProtoMessage() {}

func (x *GetLogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLogRequest.ProtoReflect.Descriptor instead.
func (*GetLogRequest) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{5}
}

type GetLogReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetLogReply) Reset() {
	*x = GetLogReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetLogReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLogReply) ProtoMessage() {}

func (x *GetLogReply) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLogReply.ProtoReflect.Descriptor instead.
func (*GetLogReply) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{6}
}

type PushLogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Body *PushLogRequest_Body `protobuf:"bytes,1,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *PushLogRequest) Reset() {
	*x = PushLogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushLogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushLogRequest) ProtoMessage() {}

func (x *PushLogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushLogRequest.ProtoReflect.Descriptor instead.
func (*PushLogRequest) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{7}
}

func (x *PushLogRequest) GetBody() *PushLogRequest_Body {
	if x != nil {
		return x.Body
	}
	return nil
}

type GetHeadLogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetHeadLogRequest) Reset() {
	*x = GetHeadLogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHeadLogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHeadLogRequest) ProtoMessage() {}

func (x *GetHeadLogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHeadLogRequest.ProtoReflect.Descriptor instead.
func (*GetHeadLogRequest) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{8}
}

type PushLogReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PushLogReply) Reset() {
	*x = PushLogReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushLogReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushLogReply) ProtoMessage() {}

func (x *PushLogReply) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushLogReply.ProtoReflect.Descriptor instead.
func (*PushLogReply) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{9}
}

type GetHeadLogReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetHeadLogReply) Reset() {
	*x = GetHeadLogReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHeadLogReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHeadLogReply) ProtoMessage() {}

func (x *GetHeadLogReply) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHeadLogReply.ProtoReflect.Descriptor instead.
func (*GetHeadLogReply) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{10}
}

// Record is a thread record containing link data.
type Document_Log struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// block is the top-level node's raw data as an ipld.Block.
	Block []byte `protobuf:"bytes,1,opt,name=block,proto3" json:"block,omitempty"`
}

func (x *Document_Log) Reset() {
	*x = Document_Log{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Document_Log) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Document_Log) ProtoMessage() {}

func (x *Document_Log) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Document_Log.ProtoReflect.Descriptor instead.
func (*Document_Log) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Document_Log) GetBlock() []byte {
	if x != nil {
		return x.Block
	}
	return nil
}

type PushLogRequest_Body struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// docKey is the DocKey of the document that is affected by the log.
	DocKey []byte `protobuf:"bytes,1,opt,name=docKey,proto3" json:"docKey,omitempty"`
	// cid is the CID of the composite of the document.
	Cid []byte `protobuf:"bytes,2,opt,name=cid,proto3" json:"cid,omitempty"`
	// schemaRoot is the SchemaRoot of the collection that the document resides in.
	SchemaRoot []byte `protobuf:"bytes,3,opt,name=schemaRoot,proto3" json:"schemaRoot,omitempty"`
	// creator is the PeerID of the peer that created the log.
	Creator string `protobuf:"bytes,4,opt,name=creator,proto3" json:"creator,omitempty"`
	// log hold the block that represent version of the document.
	Log *Document_Log `protobuf:"bytes,6,opt,name=log,proto3" json:"log,omitempty"`
}

func (x *PushLogRequest_Body) Reset() {
	*x = PushLogRequest_Body{}
	if protoimpl.UnsafeEnabled {
		mi := &file_net_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushLogRequest_Body) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushLogRequest_Body) ProtoMessage() {}

func (x *PushLogRequest_Body) ProtoReflect() protoreflect.Message {
	mi := &file_net_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushLogRequest_Body.ProtoReflect.Descriptor instead.
func (*PushLogRequest_Body) Descriptor() ([]byte, []int) {
	return file_net_proto_rawDescGZIP(), []int{7, 0}
}

func (x *PushLogRequest_Body) GetDocKey() []byte {
	if x != nil {
		return x.DocKey
	}
	return nil
}

func (x *PushLogRequest_Body) GetCid() []byte {
	if x != nil {
		return x.Cid
	}
	return nil
}

func (x *PushLogRequest_Body) GetSchemaRoot() []byte {
	if x != nil {
		return x.SchemaRoot
	}
	return nil
}

func (x *PushLogRequest_Body) GetCreator() string {
	if x != nil {
		return x.Creator
	}
	return ""
}

func (x *PushLogRequest_Body) GetLog() *Document_Log {
	if x != nil {
		return x.Log
	}
	return nil
}

var File_net_proto protoreflect.FileDescriptor

var file_net_proto_rawDesc = []byte{
	0x0a, 0x09, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x6e, 0x65, 0x74,
	0x2e, 0x70, 0x62, 0x22, 0x53, 0x0a, 0x08, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x64, 0x6f, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x06, 0x64, 0x6f, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x65, 0x61, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x65, 0x61, 0x64, 0x1a, 0x1b, 0x0a, 0x03, 0x4c,
	0x6f, 0x67, 0x12, 0x14, 0x0a, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x22, 0x14, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x44,
	0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x12,
	0x0a, 0x10, 0x47, 0x65, 0x74, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x70,
	0x6c, 0x79, 0x22, 0x15, 0x0a, 0x13, 0x50, 0x75, 0x73, 0x68, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61,
	0x70, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x13, 0x0a, 0x11, 0x50, 0x75, 0x73,
	0x68, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x0f,
	0x0a, 0x0d, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0x0d, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0xd6,
	0x01, 0x0a, 0x0e, 0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2f, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x52, 0x04, 0x62, 0x6f,
	0x64, 0x79, 0x1a, 0x92, 0x01, 0x0a, 0x04, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x64,
	0x6f, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x64, 0x6f, 0x63,
	0x4b, 0x65, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x63, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x03, 0x63, 0x69, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x52,
	0x6f, 0x6f, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x73, 0x63, 0x68, 0x65, 0x6d,
	0x61, 0x52, 0x6f, 0x6f, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x12,
	0x26, 0x0a, 0x03, 0x6c, 0x6f, 0x67, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e,
	0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x4c,
	0x6f, 0x67, 0x52, 0x03, 0x6c, 0x6f, 0x67, 0x22, 0x13, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x48, 0x65,
	0x61, 0x64, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x0e, 0x0a, 0x0c,
	0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x11, 0x0a, 0x0f,
	0x47, 0x65, 0x74, 0x48, 0x65, 0x61, 0x64, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x32,
	0xd1, 0x02, 0x0a, 0x07, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x45, 0x0a, 0x0b, 0x47,
	0x65, 0x74, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x12, 0x1a, 0x2e, 0x6e, 0x65, 0x74,
	0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e,
	0x47, 0x65, 0x74, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x22, 0x00, 0x12, 0x48, 0x0a, 0x0c, 0x50, 0x75, 0x73, 0x68, 0x44, 0x6f, 0x63, 0x47, 0x72, 0x61,
	0x70, 0x68, 0x12, 0x1b, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x73, 0x68,
	0x44, 0x6f, 0x63, 0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x19, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x44, 0x6f, 0x63,
	0x47, 0x72, 0x61, 0x70, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x36, 0x0a, 0x06,
	0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x12, 0x15, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e,
	0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e,
	0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70,
	0x6c, 0x79, 0x22, 0x00, 0x12, 0x39, 0x0a, 0x07, 0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67, 0x12,
	0x16, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x14, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62,
	0x2e, 0x50, 0x75, 0x73, 0x68, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12,
	0x42, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x48, 0x65, 0x61, 0x64, 0x4c, 0x6f, 0x67, 0x12, 0x19, 0x2e,
	0x6e, 0x65, 0x74, 0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x74, 0x48, 0x65, 0x61, 0x64, 0x4c, 0x6f,
	0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x70,
	0x62, 0x2e, 0x47, 0x65, 0x74, 0x48, 0x65, 0x61, 0x64, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x70, 0x6c,
	0x79, 0x22, 0x00, 0x42, 0x0a, 0x5a, 0x08, 0x2f, 0x3b, 0x6e, 0x65, 0x74, 0x5f, 0x70, 0x62, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_net_proto_rawDescOnce sync.Once
	file_net_proto_rawDescData = file_net_proto_rawDesc
)

func file_net_proto_rawDescGZIP() []byte {
	file_net_proto_rawDescOnce.Do(func() {
		file_net_proto_rawDescData = protoimpl.X.CompressGZIP(file_net_proto_rawDescData)
	})
	return file_net_proto_rawDescData
}

var file_net_proto_msgTypes = make([]protoimpl.MessageInfo, 13)
var file_net_proto_goTypes = []interface{}{
	(*Document)(nil),            // 0: net.pb.Document
	(*GetDocGraphRequest)(nil),  // 1: net.pb.GetDocGraphRequest
	(*GetDocGraphReply)(nil),    // 2: net.pb.GetDocGraphReply
	(*PushDocGraphRequest)(nil), // 3: net.pb.PushDocGraphRequest
	(*PushDocGraphReply)(nil),   // 4: net.pb.PushDocGraphReply
	(*GetLogRequest)(nil),       // 5: net.pb.GetLogRequest
	(*GetLogReply)(nil),         // 6: net.pb.GetLogReply
	(*PushLogRequest)(nil),      // 7: net.pb.PushLogRequest
	(*GetHeadLogRequest)(nil),   // 8: net.pb.GetHeadLogRequest
	(*PushLogReply)(nil),        // 9: net.pb.PushLogReply
	(*GetHeadLogReply)(nil),     // 10: net.pb.GetHeadLogReply
	(*Document_Log)(nil),        // 11: net.pb.Document.Log
	(*PushLogRequest_Body)(nil), // 12: net.pb.PushLogRequest.Body
}
var file_net_proto_depIdxs = []int32{
	12, // 0: net.pb.PushLogRequest.body:type_name -> net.pb.PushLogRequest.Body
	11, // 1: net.pb.PushLogRequest.Body.log:type_name -> net.pb.Document.Log
	1,  // 2: net.pb.Service.GetDocGraph:input_type -> net.pb.GetDocGraphRequest
	3,  // 3: net.pb.Service.PushDocGraph:input_type -> net.pb.PushDocGraphRequest
	5,  // 4: net.pb.Service.GetLog:input_type -> net.pb.GetLogRequest
	7,  // 5: net.pb.Service.PushLog:input_type -> net.pb.PushLogRequest
	8,  // 6: net.pb.Service.GetHeadLog:input_type -> net.pb.GetHeadLogRequest
	2,  // 7: net.pb.Service.GetDocGraph:output_type -> net.pb.GetDocGraphReply
	4,  // 8: net.pb.Service.PushDocGraph:output_type -> net.pb.PushDocGraphReply
	6,  // 9: net.pb.Service.GetLog:output_type -> net.pb.GetLogReply
	9,  // 10: net.pb.Service.PushLog:output_type -> net.pb.PushLogReply
	10, // 11: net.pb.Service.GetHeadLog:output_type -> net.pb.GetHeadLogReply
	7,  // [7:12] is the sub-list for method output_type
	2,  // [2:7] is the sub-list for method input_type
	2,  // [2:2] is the sub-list for extension type_name
	2,  // [2:2] is the sub-list for extension extendee
	0,  // [0:2] is the sub-list for field type_name
}

func init() { file_net_proto_init() }
func file_net_proto_init() {
	if File_net_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_net_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Document); i {
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
		file_net_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetDocGraphRequest); i {
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
		file_net_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetDocGraphReply); i {
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
		file_net_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushDocGraphRequest); i {
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
		file_net_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushDocGraphReply); i {
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
		file_net_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetLogRequest); i {
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
		file_net_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetLogReply); i {
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
		file_net_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushLogRequest); i {
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
		file_net_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHeadLogRequest); i {
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
		file_net_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushLogReply); i {
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
		file_net_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHeadLogReply); i {
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
		file_net_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Document_Log); i {
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
		file_net_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushLogRequest_Body); i {
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
			RawDescriptor: file_net_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   13,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_net_proto_goTypes,
		DependencyIndexes: file_net_proto_depIdxs,
		MessageInfos:      file_net_proto_msgTypes,
	}.Build()
	File_net_proto = out.File
	file_net_proto_rawDesc = nil
	file_net_proto_goTypes = nil
	file_net_proto_depIdxs = nil
}
