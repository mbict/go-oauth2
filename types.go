package oauth2

type ClientId string
type Client interface {
	ClientId() ClientId
	ClientSecret() string
	Name() string
	RedirectUri() []string
	Scope() Scope
}

type Code interface {
	ClientId() ClientId
	Session() Session
	Code() string
	RedirectUri() string
	State() string
}

type TokenType string

const (
	REFRESH_TOKEN = "refresh_token"
	ACCESS_TOKEN  = "access_token"
)

type Token interface {
	ClientId() ClientId
	Token() string
	Scope() Scope
	Type() TokenType
	Session() Session
}

type Session interface {
	Username() string
}

type GrantType string

const (
//PASSWORD           GrantType = "password"
//AUTHORIZATION_CODE GrantType = "authorization_code"
//CLIENT_CREDENTIALS GrantType = "client_credentials"
//REFRESH_TOKEN      GrantType = "refresh_token"
)

func (g GrantType) String() string {
	return string(g)
}

type ResponseType string
type ResponseTypes []ResponseType

func (rts ResponseTypes) Contains(responseType ResponseType) bool {
	for _, rt := range rts {
		if rt == responseType {
			return true
		}
	}
	return false
}

const (
	CODE     ResponseType = "code"
	ID_TOKEN ResponseType = "id_token"
	TOKEN    ResponseType = "token"
)
