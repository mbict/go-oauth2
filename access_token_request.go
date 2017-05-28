package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type AccessTokenRequest struct {
	Request
	code        string
	redirectUri *url.URL
}

func (r *AccessTokenRequest) Code() string {
	return r.code
}

func (r *AccessTokenRequest) RedirectUri() *url.URL {
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

		code := req.PostFormValue("code")
		if len(code) == 0 {
			return nil, ErrInvalidCode
		}

		return &AccessTokenRequest{
			Request: &request{
				requestedAt: time.Now(),
				client:      client,
				//session
				requestValue: req.Form,
				//requestedScopes: scope,
				//grantedScopes:   nil,
			},
			code:        code,
			redirectUri: redirectUri,
		}, nil
	}
}
