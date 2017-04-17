package oauth2

type GrantType string

const (
	PASSWORD           GrantType = "password"
	AUTHORIZATION_CODE GrantType = "authorization_code"
	CLIENT_CREDENTIALS GrantType = "client_credentials"
	REFRESH_TOKEN      GrantType = "refresh_token"
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
