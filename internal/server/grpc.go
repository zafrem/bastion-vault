package server

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/model"
)

func init() {
	// Override the default "proto" codec with a JSON codec so that we can
	// use plain Go structs instead of protobuf-generated types.
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec is a gRPC codec that marshals/unmarshals messages as JSON.
type JSONCodec struct{}

func (JSONCodec) Marshal(v any) ([]byte, error)        { return json.Marshal(v) }
func (JSONCodec) Unmarshal(data []byte, v any) error   { return json.Unmarshal(data, v) }
func (JSONCodec) Name() string                          { return "proto" } // override default codec

// ---------- request / response structs ----------

type grpcAnonymizeRequest struct {
	TenantID    string             `json:"tenant_id"`
	Category    model.DataCategory `json:"category"`
	Records     []map[string]any   `json:"records"`
	Purpose     string             `json:"purpose"`
	RequesterID string             `json:"requester_id"`
	AccessLevel model.AccessLevel  `json:"access_level"`
}

type grpcDeanonymizeRequest struct {
	TenantID      string             `json:"tenant_id"`
	Category      model.DataCategory `json:"category"`
	Records       []map[string]any   `json:"records"`
	RequesterID   string             `json:"requester_id"`
	Justification string             `json:"justification"`
}

type grpcClassifyRequest struct {
	Records []map[string]any `json:"records"`
}

type grpcDetectPIIRequest struct {
	Record map[string]any `json:"record"`
}

type grpcValidateKAnonRequest struct {
	Records   []map[string]any   `json:"records"`
	Category  model.DataCategory `json:"category"`
	RequiredK int                `json:"required_k"`
}

type grpcHealthRequest struct{}

type grpcHealthResponse struct {
	Status string `json:"status"`
}

// ---------- GRPCServer ----------

// GRPCServer is the gRPC service implementation.
type GRPCServer struct {
	engine     *anonymizer.Engine
	classifier *classification.Classifier
	kanon      *kanon.Validator
	auditor    *audit.Logger
}

// NewGRPCServer creates a GRPCServer with the given dependencies.
func NewGRPCServer(eng *anonymizer.Engine, cls *classification.Classifier, kv *kanon.Validator, aud *audit.Logger) *GRPCServer {
	return &GRPCServer{
		engine:     eng,
		classifier: cls,
		kanon:      kv,
		auditor:    aud,
	}
}

// Register registers the VaultService with the given gRPC server.
func (g *GRPCServer) Register(s *grpc.Server) {
	s.RegisterService(&vaultServiceDesc, g)
}

// ---------- method handlers ----------

func (g *GRPCServer) anonymize(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcAnonymizeRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		r := req.(*grpcAnonymizeRequest)
		return g.engine.Anonymize(ctx, &model.AnonymizeRequest{
			TenantID:    r.TenantID,
			Category:    r.Category,
			Records:     r.Records,
			Purpose:     r.Purpose,
			RequesterID: r.RequesterID,
			AccessLevel: r.AccessLevel,
		})
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/Anonymize"}, handler)
	}
	return handler(ctx, &req)
}

func (g *GRPCServer) deanonymize(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcDeanonymizeRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		r := req.(*grpcDeanonymizeRequest)
		return g.engine.Deanonymize(ctx, &model.DeanonymizeRequest{
			TenantID:      r.TenantID,
			Category:      r.Category,
			Records:       r.Records,
			RequesterID:   r.RequesterID,
			Justification: r.Justification,
		})
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/Deanonymize"}, handler)
	}
	return handler(ctx, &req)
}

func (g *GRPCServer) classifyData(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcClassifyRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		r := req.(*grpcClassifyRequest)
		return g.classifier.Classify(r.Records), nil
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/ClassifyData"}, handler)
	}
	return handler(ctx, &req)
}

func (g *GRPCServer) detectPII(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcDetectPIIRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		r := req.(*grpcDetectPIIRequest)
		detections := g.classifier.DetectPII(r.Record)
		return map[string]any{"detections": detections, "count": len(detections)}, nil
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/DetectPII"}, handler)
	}
	return handler(ctx, &req)
}

func (g *GRPCServer) validateKAnon(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcValidateKAnonRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		r := req.(*grpcValidateKAnonRequest)
		if r.RequiredK == 0 {
			r.RequiredK = 5
		}
		return g.kanon.Validate(ctx, r.Records, r.Category, r.RequiredK)
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/ValidateKAnon"}, handler)
	}
	return handler(ctx, &req)
}

func (g *GRPCServer) health(ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var req grpcHealthRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return &grpcHealthResponse{Status: "ok"}, nil
	}
	if interceptor != nil {
		return interceptor(ctx, &req, &grpc.UnaryServerInfo{Server: g, FullMethod: "/bastion.vault.v1.VaultService/Health"}, handler)
	}
	return handler(ctx, &req)
}

// ---------- ServiceDesc ----------

func anonymizeHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).anonymize(ctx, dec, interceptor)
}

func deanonymizeHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).deanonymize(ctx, dec, interceptor)
}

func classifyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).classifyData(ctx, dec, interceptor)
}

func detectPIIHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).detectPII(ctx, dec, interceptor)
}

func validateKAnonHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).validateKAnon(ctx, dec, interceptor)
}

func healthHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return srv.(*GRPCServer).health(ctx, dec, interceptor)
}

var vaultServiceDesc = grpc.ServiceDesc{
	ServiceName: "bastion.vault.v1.VaultService",
	HandlerType: (*GRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Anonymize", Handler: anonymizeHandler},
		{MethodName: "Deanonymize", Handler: deanonymizeHandler},
		{MethodName: "ClassifyData", Handler: classifyHandler},
		{MethodName: "DetectPII", Handler: detectPIIHandler},
		{MethodName: "ValidateKAnon", Handler: validateKAnonHandler},
		{MethodName: "Health", Handler: healthHandler},
	},
	Streams: []grpc.StreamDesc{},
}
