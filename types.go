package oauth2

import (
	"bytes"
	"strings"
)

type ClientId string
type Client interface {
	ClientId() ClientId
	ClientSecret() string
	Name() string
	RedirectUri() []string
	GrantTypes() []GrantType
	ResponseTypes() ResponseTypes
	Scope() Scope
}

type Code interface {
	ClientId() ClientId
	Session() Session
	Code() string
	RedirectUri() string
	State() string
}

//type TokenType string
//
//const (
//	REFRESH_TOKEN = "refresh_token"
//	ACCESS_TOKEN  = "access_token"
//)

type Token interface {
	ClientId() ClientId
	Token() string
	Scope() Scope
	//	Type() TokenType
	Session() Session
}

type GrantType string

const (
	PASSWORD           = "password"
	AUTHORIZATION_CODE = "authorization_code"
	CLIENT_CREDENTIALS = "client_credentials"
	REFRESH_TOKEN      = "refresh_token"
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

func (rts ResponseTypes) String() string {
	res := bytes.NewBuffer(nil)
	for i, rt := range rts {
		if i != 0 {
			res.WriteByte(' ')
		}
		res.WriteString(string(rt))
	}
	return res.String()
}

func responseTypeFromString(str string) ResponseTypes {
	var responseTypes ResponseTypes
	for _, v := range strings.Split(str, " ") {
		s := strings.TrimSpace(v)
		if len(s) > 0 {
			responseTypes = append(responseTypes, ResponseType(s))
		}
	}
	return responseTypes
}

const (
	CODE     ResponseType = "code"
	ID_TOKEN ResponseType = "id_token"
	TOKEN    ResponseType = "token"
)
