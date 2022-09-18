// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api.proto

package api_pb

import (
	context "context"
	fmt "fmt"
	io "io"
	math "math"
	math_bits "math/bits"

	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type AddReplicatorRequest struct {
	Collection []byte `protobuf:"bytes,1,opt,name=collection,proto3" json:"collection,omitempty"`
	Addr       []byte `protobuf:"bytes,2,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (m *AddReplicatorRequest) Reset()         { *m = AddReplicatorRequest{} }
func (m *AddReplicatorRequest) String() string { return proto.CompactTextString(m) }
func (*AddReplicatorRequest) ProtoMessage()    {}
func (*AddReplicatorRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{0}
}
func (m *AddReplicatorRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AddReplicatorRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AddReplicatorRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AddReplicatorRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddReplicatorRequest.Merge(m, src)
}
func (m *AddReplicatorRequest) XXX_Size() int {
	return m.Size()
}
func (m *AddReplicatorRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AddReplicatorRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AddReplicatorRequest proto.InternalMessageInfo

func (m *AddReplicatorRequest) GetCollection() []byte {
	if m != nil {
		return m.Collection
	}
	return nil
}

func (m *AddReplicatorRequest) GetAddr() []byte {
	if m != nil {
		return m.Addr
	}
	return nil
}

type AddReplicatorReply struct {
	PeerID []byte `protobuf:"bytes,1,opt,name=peerID,proto3" json:"peerID,omitempty"`
}

func (m *AddReplicatorReply) Reset()         { *m = AddReplicatorReply{} }
func (m *AddReplicatorReply) String() string { return proto.CompactTextString(m) }
func (*AddReplicatorReply) ProtoMessage()    {}
func (*AddReplicatorReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{1}
}
func (m *AddReplicatorReply) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AddReplicatorReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AddReplicatorReply.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AddReplicatorReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddReplicatorReply.Merge(m, src)
}
func (m *AddReplicatorReply) XXX_Size() int {
	return m.Size()
}
func (m *AddReplicatorReply) XXX_DiscardUnknown() {
	xxx_messageInfo_AddReplicatorReply.DiscardUnknown(m)
}

var xxx_messageInfo_AddReplicatorReply proto.InternalMessageInfo

func (m *AddReplicatorReply) GetPeerID() []byte {
	if m != nil {
		return m.PeerID
	}
	return nil
}

func init() {
	proto.RegisterType((*AddReplicatorRequest)(nil), "api.pb.AddReplicatorRequest")
	proto.RegisterType((*AddReplicatorReply)(nil), "api.pb.AddReplicatorReply")
}

func init() { proto.RegisterFile("api.proto", fileDescriptor_00212fb1f9d3bf1c) }

var fileDescriptor_00212fb1f9d3bf1c = []byte{
	// 191 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4c, 0x2c, 0xc8, 0xd4,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x03, 0x33, 0x93, 0x94, 0xbc, 0xb8, 0x44, 0x1c, 0x53,
	0x52, 0x82, 0x52, 0x0b, 0x72, 0x32, 0x93, 0x13, 0x4b, 0xf2, 0x8b, 0x82, 0x52, 0x0b, 0x4b, 0x53,
	0x8b, 0x4b, 0x84, 0xe4, 0xb8, 0xb8, 0x92, 0xf3, 0x73, 0x72, 0x52, 0x93, 0x4b, 0x32, 0xf3, 0xf3,
	0x24, 0x18, 0x15, 0x18, 0x35, 0x78, 0x82, 0x90, 0x44, 0x84, 0x84, 0xb8, 0x58, 0x12, 0x53, 0x52,
	0x8a, 0x24, 0x98, 0xc0, 0x32, 0x60, 0xb6, 0x92, 0x0e, 0x97, 0x10, 0x9a, 0x59, 0x05, 0x39, 0x95,
	0x42, 0x62, 0x5c, 0x6c, 0x05, 0xa9, 0xa9, 0x45, 0x9e, 0x2e, 0x50, 0x53, 0xa0, 0x3c, 0xa3, 0x30,
	0x2e, 0xf6, 0xe0, 0xd4, 0xa2, 0xb2, 0xcc, 0xe4, 0x54, 0x21, 0x6f, 0x2e, 0x5e, 0x14, 0x8d, 0x42,
	0x32, 0x7a, 0x10, 0xe7, 0xe9, 0x61, 0x73, 0x9b, 0x94, 0x14, 0x0e, 0xd9, 0x82, 0x9c, 0x4a, 0x25,
	0x06, 0x27, 0x89, 0x13, 0x8f, 0xe4, 0x18, 0x2f, 0x3c, 0x92, 0x63, 0x7c, 0xf0, 0x48, 0x8e, 0x71,
	0xc2, 0x63, 0x39, 0x86, 0x0b, 0x8f, 0xe5, 0x18, 0x6e, 0x3c, 0x96, 0x63, 0x48, 0x62, 0x03, 0x7b,
	0xdd, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0xcb, 0x02, 0x68, 0xde, 0x07, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ServiceClient is the client API for Service service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ServiceClient interface {
	// AddReplicator for this peer
	AddReplicator(ctx context.Context, in *AddReplicatorRequest, opts ...grpc.CallOption) (*AddReplicatorReply, error)
}

type serviceClient struct {
	cc *grpc.ClientConn
}

func NewServiceClient(cc *grpc.ClientConn) ServiceClient {
	return &serviceClient{cc}
}

func (c *serviceClient) AddReplicator(ctx context.Context, in *AddReplicatorRequest, opts ...grpc.CallOption) (*AddReplicatorReply, error) {
	out := new(AddReplicatorReply)
	err := c.cc.Invoke(ctx, "/api.pb.Service/AddReplicator", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServiceServer is the server API for Service service.
type ServiceServer interface {
	// AddReplicator for this peer
	AddReplicator(context.Context, *AddReplicatorRequest) (*AddReplicatorReply, error)
}

// UnimplementedServiceServer can be embedded to have forward compatible implementations.
type UnimplementedServiceServer struct {
}

func (*UnimplementedServiceServer) AddReplicator(ctx context.Context, req *AddReplicatorRequest) (*AddReplicatorReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddReplicator not implemented")
}

func RegisterServiceServer(s *grpc.Server, srv ServiceServer) {
	s.RegisterService(&_Service_serviceDesc, srv)
}

func _Service_AddReplicator_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(AddReplicatorRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).AddReplicator(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.pb.Service/AddReplicator",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(ServiceServer).AddReplicator(ctx, req.(*AddReplicatorRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Service_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.pb.Service",
	HandlerType: (*ServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddReplicator",
			Handler:    _Service_AddReplicator_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

func (m *AddReplicatorRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AddReplicatorRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddReplicatorRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Addr) > 0 {
		i -= len(m.Addr)
		copy(dAtA[i:], m.Addr)
		i = encodeVarintApi(dAtA, i, uint64(len(m.Addr)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Collection) > 0 {
		i -= len(m.Collection)
		copy(dAtA[i:], m.Collection)
		i = encodeVarintApi(dAtA, i, uint64(len(m.Collection)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *AddReplicatorReply) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AddReplicatorReply) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddReplicatorReply) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.PeerID) > 0 {
		i -= len(m.PeerID)
		copy(dAtA[i:], m.PeerID)
		i = encodeVarintApi(dAtA, i, uint64(len(m.PeerID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintApi(dAtA []byte, offset int, v uint64) int {
	offset -= sovApi(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *AddReplicatorRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Collection)
	if l > 0 {
		n += 1 + l + sovApi(uint64(l))
	}
	l = len(m.Addr)
	if l > 0 {
		n += 1 + l + sovApi(uint64(l))
	}
	return n
}

func (m *AddReplicatorReply) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.PeerID)
	if l > 0 {
		n += 1 + l + sovApi(uint64(l))
	}
	return n
}

func sovApi(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozApi(x uint64) (n int) {
	return sovApi(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *AddReplicatorRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowApi
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AddReplicatorRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AddReplicatorRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Collection", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthApi
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthApi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Collection = append(m.Collection[:0], dAtA[iNdEx:postIndex]...)
			if m.Collection == nil {
				m.Collection = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addr", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthApi
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthApi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addr = append(m.Addr[:0], dAtA[iNdEx:postIndex]...)
			if m.Addr == nil {
				m.Addr = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipApi(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthApi
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthApi
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AddReplicatorReply) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowApi
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AddReplicatorReply: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AddReplicatorReply: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PeerID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApi
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthApi
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthApi
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PeerID = append(m.PeerID[:0], dAtA[iNdEx:postIndex]...)
			if m.PeerID == nil {
				m.PeerID = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipApi(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthApi
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthApi
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipApi(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowApi
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowApi
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowApi
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthApi
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupApi
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthApi
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthApi        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowApi          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupApi = fmt.Errorf("proto: unexpected end of group")
)
