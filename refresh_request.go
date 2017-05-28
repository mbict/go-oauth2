package oauth2

import (
	"context"
	"net/http"
	"time"
)

type RefreshRequest struct {
	Request
	refreshToken string
}

func (r *RefreshRequest) RefreshToken() string {
	return r.refreshToken
}

func DecodeRefreshRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		if req.FormValue("grant_type") != REFRESH_TOKEN {
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

		refreshToken := req.PostFormValue("refresh_token")
		if len(refreshToken) == 0 {
			return nil, ErrInvalidToken
		}

		scope := scopeFromString(req.FormValue("scope"))

		return &RefreshRequest{
			Request: &request{
				requestedAt:     time.Now(),
				client:          client,
				requestedScopes: scope,
				requestValue:    req.Form,
			},
			refreshToken: refreshToken,
		}, nil
	}
}
