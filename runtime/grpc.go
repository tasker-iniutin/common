package runtime

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func ServeGRPC(
	addr string,
	register func(*grpc.Server),
	enableReflection bool,
	opts ...grpc.ServerOption,
) error {
	server := grpc.NewServer(opts...)
	register(server)

	if enableReflection {
		reflection.Register(server)
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	if err := server.Serve(lis); err != nil {
		return fmt.Errorf("serve grpc: %w", err)
	}

	return nil
}
