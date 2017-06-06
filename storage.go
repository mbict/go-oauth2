package oauth2

import (
	"context"
	"errors"
)

var (
	ErrClientNotFound  = errors.New("client not found")
	ErrSessionNotFound = errors.New("session not found")
	ErrCodeNotFound    = errors.New("code not found")
	ErrTokenNotFound   = errors.New("token not found")
)

type Oauth2Storage interface {
	TokenStorage
	ClientStorage
	UserStorage
}

type TokenStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(ctx context.Context, code string, req AuthorizeRequest) error
	GetAuthorizeCodeSession(ctx context.Context, code string) (Session, error)
	DeleteAuthorizeCodeSession(ctx context.Context, code string) (bool, error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, req Request) error
	GetAccessTokenSession(ctx context.Context, signature string) (Session, error)
	DeleteAccessTokenSession(ctx context.Context, signature string) (bool, error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, req Request) error
	GetRefreshTokenSession(ctx context.Context, signature string) (Session, error)
	DeleteRefreshTokenSession(ctx context.Context, signature string) (bool, error)
}

type ClientStorage interface {
	AuthenticateClient(ctx context.Context, clientId string, secret string) (Client, error)
	GetClient(ctx context.Context, clientId string) (Client, error)
}

type UserStorage interface {
	AuthenticateUser(ctx context.Context, username string, password string) (string, error)
}
