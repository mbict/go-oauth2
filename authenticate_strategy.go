package oauth2

import (
	"context"
	"net/url"
)

type AuthenticateStrategyFunc func(context.Context, *AuthorizeRequest) (Response, error)

//NewAutenticateRedirectStrategy creates a default redirection strategy and append all the data to the url
func NewAuthenticateRedirectStrategy(uri string) AuthenticateStrategyFunc {
	baseUrl, err := url.Parse(uri)
	if err != nil {
		panic(err)
	}
	return func(ctx context.Context, r *AuthorizeRequest) (Response, error) {
		redirectUrl := &url.URL{
			Scheme:     baseUrl.Scheme,
			Opaque:     baseUrl.Opaque,
			User:       baseUrl.User,
			Host:       baseUrl.Host,
			Path:       baseUrl.Path,
			RawPath:    baseUrl.RawPath,
			ForceQuery: baseUrl.ForceQuery,
			RawQuery:   "",
			Fragment:   baseUrl.Fragment,
		}

		q := baseUrl.Query()
		q.Set("client_id", string(r.ClientId))
		q.Set("response_type", r.ResponseTypes.String())
		q.Set("redirect_uri", r.RedirectUri.String())
		if len(r.Scope) > 0 {
			q.Set("scope", r.Scope.String())
		}
		if r.State != "" {
			q.Set("state", r.State)
		}
		redirectUrl.RawQuery = q.Encode()

		return &AuthenticateResponse{
			RedirectUri: redirectUrl,
		}, nil
	}
}
