package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type AccessTokenRequest interface {
	Request
	Code() string
	RedirectUri() *url.URL
}

type accessTokenRequest struct {
	Request
	code        string
	redirectUri *url.URL
}

func (r *accessTokenRequest) Code() string {
	return r.code
}

func (r *accessTokenRequest) RedirectUri() *url.URL {
	return r.redirectUri
}

func DecodeAccessTokenRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		if req.PostFormValue("grant_type") != AUTHORIZATION_CODE {
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

		//redirect url parsing and encoding
		rawRedirectUri := req.PostFormValue("redirect_uri")
		if len(rawRedirectUri) == 0 {
			return nil, ErrInvalidRequest
		}

		redirectUri, err := url.Parse(rawRedirectUri)
		if err != nil || redirectUri.IsAbs() == false {
			return nil, ErrInvalidRedirectUri
		}

		// validate redirect uri is registered for this client
		if !hasRedirectUri(client.RedirectUri(), redirectUri.String()) {
			return nil, ErrInvalidRedirectUri
		}

		code := req.PostFormValue("code")
		if len(code) == 0 {
			return nil, ErrInvalidCode
		}

		return &accessTokenRequest{
			Request: &request{
				requestedAt:  time.Now(),
				client:       client,
				requestValue: req.Form,
			},
			code:        code,
			redirectUri: redirectUri,
		}, nil
	}
}
