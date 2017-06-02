package oauth2

import (
	"context"
	"time"
)

type TokenStrategy interface {
	AuthorizeCodeStrategy
	AccessTokenStrategy
	RefreshTokenStrategy
}

type AuthorizeCodeStrategy interface {
	AuthorizeCodeSignature(token string) (string, error)
	GenerateAuthorizeCode(ctx context.Context, request Request) (signature string, token string, err error)
	ValidateAuthorizeCode(ctx context.Context, request Request, token string) (err error)
	AuthorizeCodeLifespan() time.Duration
}

type AccessTokenStrategy interface {
	AccessTokenSignature(token string) (string, error)
	GenerateAccessToken(ctx context.Context, request Request) (signature string, token string, err error)
	ValidateAccessToken(ctx context.Context, request Request, token string) (err error)
	AccessTokenLifespan() time.Duration
}

type RefreshTokenStrategy interface {
	RefreshTokenSignature(token string) (string, error)
	GenerateRefreshToken(ctx context.Context, request Request) (signature string, token string, err error)
	ValidateRefreshToken(ctx context.Context, request Request, token string) (err error)
}
