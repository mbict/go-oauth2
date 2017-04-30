package oauth2

import (
	"context"
	"net/http"
)

type IntrospectRequest struct {
	clientId     ClientId
	clientSecret string
	token        string
	tokenType    TokenType
}

func (_ *IntrospectRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	if req.FormValue("grant_type") != "password" {
		return nil, nil
	}

	clientId, clientSecret := resolveClientCredentials(req)
	token := req.PostFormValue("token")
	tokenType := req.PostFormValue("token_type")
	return &IntrospectRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		token:        token,
		tokenType:    TokenType(tokenType),
	}, nil
}
