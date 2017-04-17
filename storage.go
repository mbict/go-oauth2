package oauth2

import (
	"errors"
)

var (
	ErrCodeNotFound  = errors.New("code not found")
	ErrTokenNotFound = errors.New("token not found")
)

type Code struct {
	ClientId    ClientId
	Session     *Session
	Code        string
	RedirectUri string
	State       string
}

type TokenType string

type Token struct {
	ClientId ClientId
	Token    string
	Scope    Scope
	Type     TokenType
	Session  *Session
}

type TokenStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(code string) error
	GetAuthorizeCodeSession(code string) (*Code, error)
	DeleteAuthorizeCodeSession(code string) (bool, error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(signature string) error
	GetAccessTokenSession(signature string) (*Token, error)
	DeleteAccessTokenSession(signature string) (bool, error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(signature string) error
	GetRefreshTokenSession(signature string) (*Token, error)
	DeleteRefreshTokenSession(signature string) (bool, error)
}

type ClientStorage interface {
	Authenticate(clientId ClientId, secret string) (*Client, error)
	GetClient(clientId ClientId) (*Client, error)
}

type UserStorage interface {
	Authenticate(username string, password string) (string, error)
}

type Session struct {
	Username string
}

type SessionStorage interface {
	NewSession() error
}
