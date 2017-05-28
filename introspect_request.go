package oauth2

import (
	"context"
	"net/http"
	"time"
)

type IntrospectRequest struct {
	Request
	token     string
	tokenType string
}

func DecodeIntrospectRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {

		clientId, clientSecret := resolveClientCredentials(req)
		if clientId == "" || clientSecret == "" {
			return nil, ErrInvalidRequest
		}

		client, err := storage.AuthenticateClient(ctx, clientId, clientSecret)
		if err == ErrUnauthorizedClient {
			return nil, ErrUnauthorizedClient
		}
		if err != nil {
			return nil, ErrServerError
		}

		scope := scopeFromString(req.PostForm.Get("scope"))
		token := req.PostFormValue("token")
		tokenType := req.PostFormValue("token_type")
		return &IntrospectRequest{
			Request: &request{
				requestedAt:     time.Now(),
				requestedScopes: scope,
				client:          client,
				session:         &session{},
			},
			token:     token,
			tokenType: tokenType,
		}, nil
	}
}
