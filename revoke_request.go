package oauth2

import (
	"context"
	"net/http"
)

type RevokeTokenRequest struct {
	Request
	clientId     ClientId
	clientSecret string
	token        string
	tokenType    string
}

func DecodeRevokeRequest(ctx context.Context, req *http.Request) (Request, error) {
	clientId, clientSecret := resolveClientCredentials(req)
	token := req.PostFormValue("token")
	tokenType := req.PostFormValue("token_type")
	return &RevokeTokenRequest{
		clientId:     ClientId(clientId),
		clientSecret: clientSecret,
		token:        token,
		tokenType:    tokenType,
	}, nil
}
