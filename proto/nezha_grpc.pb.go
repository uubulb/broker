// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.27.3
// source: proto/nezha.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	NezhaService_ReportSystemState_FullMethodName = "/proto.NezhaService/ReportSystemState"
	NezhaService_ReportSystemInfo_FullMethodName  = "/proto.NezhaService/ReportSystemInfo"
	NezhaService_ReportTask_FullMethodName        = "/proto.NezhaService/ReportTask"
	NezhaService_RequestTask_FullMethodName       = "/proto.NezhaService/RequestTask"
	NezhaService_IOStream_FullMethodName          = "/proto.NezhaService/IOStream"
	NezhaService_LookupGeoIP_FullMethodName       = "/proto.NezhaService/LookupGeoIP"
)

// NezhaServiceClient is the client API for NezhaService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type NezhaServiceClient interface {
	ReportSystemState(ctx context.Context, in *State, opts ...grpc.CallOption) (*Receipt, error)
	ReportSystemInfo(ctx context.Context, in *Host, opts ...grpc.CallOption) (*Receipt, error)
	ReportTask(ctx context.Context, in *TaskResult, opts ...grpc.CallOption) (*Receipt, error)
	RequestTask(ctx context.Context, in *Host, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Task], error)
	IOStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[IOStreamData, IOStreamData], error)
	LookupGeoIP(ctx context.Context, in *GeoIP, opts ...grpc.CallOption) (*GeoIP, error)
}

type nezhaServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewNezhaServiceClient(cc grpc.ClientConnInterface) NezhaServiceClient {
	return &nezhaServiceClient{cc}
}

func (c *nezhaServiceClient) ReportSystemState(ctx context.Context, in *State, opts ...grpc.CallOption) (*Receipt, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Receipt)
	err := c.cc.Invoke(ctx, NezhaService_ReportSystemState_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nezhaServiceClient) ReportSystemInfo(ctx context.Context, in *Host, opts ...grpc.CallOption) (*Receipt, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Receipt)
	err := c.cc.Invoke(ctx, NezhaService_ReportSystemInfo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nezhaServiceClient) ReportTask(ctx context.Context, in *TaskResult, opts ...grpc.CallOption) (*Receipt, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Receipt)
	err := c.cc.Invoke(ctx, NezhaService_ReportTask_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nezhaServiceClient) RequestTask(ctx context.Context, in *Host, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Task], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &NezhaService_ServiceDesc.Streams[0], NezhaService_RequestTask_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Host, Task]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type NezhaService_RequestTaskClient = grpc.ServerStreamingClient[Task]

func (c *nezhaServiceClient) IOStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[IOStreamData, IOStreamData], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &NezhaService_ServiceDesc.Streams[1], NezhaService_IOStream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[IOStreamData, IOStreamData]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type NezhaService_IOStreamClient = grpc.BidiStreamingClient[IOStreamData, IOStreamData]

func (c *nezhaServiceClient) LookupGeoIP(ctx context.Context, in *GeoIP, opts ...grpc.CallOption) (*GeoIP, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GeoIP)
	err := c.cc.Invoke(ctx, NezhaService_LookupGeoIP_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NezhaServiceServer is the server API for NezhaService service.
// All implementations should embed UnimplementedNezhaServiceServer
// for forward compatibility.
type NezhaServiceServer interface {
	ReportSystemState(context.Context, *State) (*Receipt, error)
	ReportSystemInfo(context.Context, *Host) (*Receipt, error)
	ReportTask(context.Context, *TaskResult) (*Receipt, error)
	RequestTask(*Host, grpc.ServerStreamingServer[Task]) error
	IOStream(grpc.BidiStreamingServer[IOStreamData, IOStreamData]) error
	LookupGeoIP(context.Context, *GeoIP) (*GeoIP, error)
}

// UnimplementedNezhaServiceServer should be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedNezhaServiceServer struct{}

func (UnimplementedNezhaServiceServer) ReportSystemState(context.Context, *State) (*Receipt, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportSystemState not implemented")
}
func (UnimplementedNezhaServiceServer) ReportSystemInfo(context.Context, *Host) (*Receipt, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportSystemInfo not implemented")
}
func (UnimplementedNezhaServiceServer) ReportTask(context.Context, *TaskResult) (*Receipt, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportTask not implemented")
}
func (UnimplementedNezhaServiceServer) RequestTask(*Host, grpc.ServerStreamingServer[Task]) error {
	return status.Errorf(codes.Unimplemented, "method RequestTask not implemented")
}
func (UnimplementedNezhaServiceServer) IOStream(grpc.BidiStreamingServer[IOStreamData, IOStreamData]) error {
	return status.Errorf(codes.Unimplemented, "method IOStream not implemented")
}
func (UnimplementedNezhaServiceServer) LookupGeoIP(context.Context, *GeoIP) (*GeoIP, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LookupGeoIP not implemented")
}
func (UnimplementedNezhaServiceServer) testEmbeddedByValue() {}

// UnsafeNezhaServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to NezhaServiceServer will
// result in compilation errors.
type UnsafeNezhaServiceServer interface {
	mustEmbedUnimplementedNezhaServiceServer()
}

func RegisterNezhaServiceServer(s grpc.ServiceRegistrar, srv NezhaServiceServer) {
	// If the following call pancis, it indicates UnimplementedNezhaServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&NezhaService_ServiceDesc, srv)
}

func _NezhaService_ReportSystemState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(State)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NezhaServiceServer).ReportSystemState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NezhaService_ReportSystemState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NezhaServiceServer).ReportSystemState(ctx, req.(*State))
	}
	return interceptor(ctx, in, info, handler)
}

func _NezhaService_ReportSystemInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Host)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NezhaServiceServer).ReportSystemInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NezhaService_ReportSystemInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NezhaServiceServer).ReportSystemInfo(ctx, req.(*Host))
	}
	return interceptor(ctx, in, info, handler)
}

func _NezhaService_ReportTask_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TaskResult)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NezhaServiceServer).ReportTask(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NezhaService_ReportTask_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NezhaServiceServer).ReportTask(ctx, req.(*TaskResult))
	}
	return interceptor(ctx, in, info, handler)
}

func _NezhaService_RequestTask_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Host)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(NezhaServiceServer).RequestTask(m, &grpc.GenericServerStream[Host, Task]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type NezhaService_RequestTaskServer = grpc.ServerStreamingServer[Task]

func _NezhaService_IOStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(NezhaServiceServer).IOStream(&grpc.GenericServerStream[IOStreamData, IOStreamData]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type NezhaService_IOStreamServer = grpc.BidiStreamingServer[IOStreamData, IOStreamData]

func _NezhaService_LookupGeoIP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GeoIP)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NezhaServiceServer).LookupGeoIP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NezhaService_LookupGeoIP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NezhaServiceServer).LookupGeoIP(ctx, req.(*GeoIP))
	}
	return interceptor(ctx, in, info, handler)
}

// NezhaService_ServiceDesc is the grpc.ServiceDesc for NezhaService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var NezhaService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.NezhaService",
	HandlerType: (*NezhaServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ReportSystemState",
			Handler:    _NezhaService_ReportSystemState_Handler,
		},
		{
			MethodName: "ReportSystemInfo",
			Handler:    _NezhaService_ReportSystemInfo_Handler,
		},
		{
			MethodName: "ReportTask",
			Handler:    _NezhaService_ReportTask_Handler,
		},
		{
			MethodName: "LookupGeoIP",
			Handler:    _NezhaService_LookupGeoIP_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RequestTask",
			Handler:       _NezhaService_RequestTask_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "IOStream",
			Handler:       _NezhaService_IOStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "proto/nezha.proto",
}