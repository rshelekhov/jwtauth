package jwtauth

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type contextKey string

const (
	AccessTokenCtxKey contextKey = "access_token"
)

func GetTokenFromContext(ctx context.Context) (string, error) {
	token, ok := ctx.Value(AccessTokenCtxKey).(string)
	if !ok {
		return "", ErrTokenNotFoundInCtx
	}

	return token, nil
}

func AddAccessTokenToMetadata(ctx context.Context) (context.Context, error) {
	accessToken, ok := ctx.Value(AccessTokenCtxKey).(string)
	if !ok {
		return nil, ErrAccessTokenNotFoundInCtx
	}

	md := metadata.Pairs(AccessTokenKey, accessToken)

	newCtx := metadata.NewOutgoingContext(ctx, md)

	return newCtx, nil
}
