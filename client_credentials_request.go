package oauth2

import (
	"context"
	"net/http"
	"time"
)

type ClientCredentialsRequest struct {
	Request
}

func DecodeClientCredentialsRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		if req.FormValue("grant_type") != CLIENT_CREDENTIALS {
			return nil, nil
		}

		clientId, clientSecret := resolveClientCredentials(req)
		if clientId == "" || clientSecret == "" {
			return nil, ErrInvalidRequest
		}

		client, err := storage.AuthenticateClient(ctx, clientId, clientSecret)
		if err != nil {
			return nil, err
		}

		scope := scopeFromString(req.FormValue("scope"))

		return &ClientCredentialsRequest{
			Request: &request{
				requestedAt:     time.Now(),
				client:          client,
				requestedScopes: scope,
				requestValue:    req.PostForm,
			},
		}, nil
	}
}
