package authctx

import "context"

type key struct{}

func WithUserID(ctx context.Context, id uint64) context.Context {
	return context.WithValue(ctx, key{}, id)
}

func UserID(ctx context.Context) (uint64, bool) {
	v := ctx.Value(key{})
	id, ok := v.(uint64)
	return id, ok
}
