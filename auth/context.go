package auth

import (
	"context"
)

type contextKey string

const claimsKey contextKey = "authClaims"

func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func FromContext(ctx context.Context) (*Claims, bool) {
	v := ctx.Value(claimsKey)
	if v == nil {
		return nil, false
	}
	c, ok := v.(*Claims)
	return c, ok
}
