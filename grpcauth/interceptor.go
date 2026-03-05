package grpcauth

import (
	"context"
	"strings"

	"github.com/tasker-iniutin/common/authctx"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Verifier interface {
	VerifyAccess(tokenStr string) (userID uint64, err error)
}

func UnaryAuthInterceptor(v Verifier, whitelist map[string]struct{}) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, ok := whitelist[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		auth := first(md.Get("authorization"))
		if auth == "" {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}

		token := extractBearer(auth)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "bad authorization")
		}

		userID, err := v.VerifyAccess(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		ctx = authctx.WithUserID(ctx, userID)
		return handler(ctx, req)
	}
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func extractBearer(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
