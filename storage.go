package oauth2

import (
	"errors"
)

var (
	ErrClientNotFound  = errors.New("client not found")
	ErrSessionNotFound = errors.New("session not found")
	ErrCodeNotFound    = errors.New("code not found")
	ErrTokenNotFound   = errors.New("token not found")
)

type TokenStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(code string) error
	GetAuthorizeCodeSession(code string) (Code, error)
	DeleteAuthorizeCodeSession(code string) (bool, error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(signature string) error
	GetAccessTokenSession(signature string) (Token, error)
	DeleteAccessTokenSession(signature string) (bool, error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(signature string) error
	GetRefreshTokenSession(signature string) (Token, error)
	DeleteRefreshTokenSession(signature string) (bool, error)
}

type ClientStorage interface {
	AuthenticateClient(clientId ClientId, secret string) (Client, error)
	GetClient(clientId ClientId) (Client, error)
}

type UserStorage interface {
	AuthenticateUser(username string, password string) (string, error)
}

type SessionStorage interface {
	NewSession(clientId ClientId, username string) error
	GetSession(SessionId) (Session, error)
}
