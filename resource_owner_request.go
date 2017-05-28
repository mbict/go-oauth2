package oauth2

import (
	"context"
	"net/http"
	"time"
)

type ResourceOwnerRequest struct {
	Request
}

func DecodeResourceOwnerRequest(clientStorage ClientStorage, userStorage UserStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		if req.FormValue("grant_type") != PASSWORD {
			return nil, nil
		}

		clientId, clientSecret := resolveClientCredentials(req)
		if clientId == "" || clientSecret == "" {
			return nil, ErrInvalidRequest
		}

		client, err := clientStorage.AuthenticateClient(ctx, clientId, clientSecret)
		if err != nil {
			return nil, err
		}

		username := req.PostFormValue("username")
		password := req.PostFormValue("password")
		if len(username) == 0 || len(password) == 0 {
			return nil, ErrInvalidRequest
		}
		userId, err := userStorage.AuthenticateUser(ctx, username, password)
		if err != nil {
			return nil, err
		}

		scope := scopeFromString(req.FormValue("scope"))

		return &ResourceOwnerRequest{
			Request: &request{
				requestedAt: time.Now(),
				client:      client,
				session: &session{
					userId: userId,
				},
				requestValue:    req.Form,
				requestedScopes: scope,
			},
		}, nil
	}
}
