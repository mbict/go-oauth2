package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type AuthorizeRequest interface {
	Request
	ResponseTypes() ResponseTypes
	RedirectUri() *url.URL
	State() string
	Valid() OAuthError
}

type authorizeRequest struct {
	Request
	responseTypes ResponseTypes
	redirectUri   *url.URL
	state         string
}

func (r *authorizeRequest) ResponseTypes() ResponseTypes {
	return r.responseTypes
}

func (r *authorizeRequest) RedirectUri() *url.URL {
	return r.redirectUri
}

func (r *authorizeRequest) State() string {
	return r.state
}

func (r *authorizeRequest) Valid() OAuthError {
	//client check
	if r.Client() == nil {
		return ErrUnauthorizedClient
	}

	//redirect check
	if r.RedirectUri() == nil || hasRedirectUri(r.Client().RedirectUri(), r.RedirectUri().String()) == false {
		return ErrInvalidRedirectUri
	}

	return nil
}

func NewAuthorizeRequest(requestedAt time.Time, client Client, session Session, requestValues url.Values, requestedScopes Scope, responseTypes ResponseTypes, redirectUri *url.URL, state string) AuthorizeRequest {
	return &authorizeRequest{
		Request:       newRequest(requestedAt, client, session, requestValues, requestedScopes),
		responseTypes: responseTypes,
		redirectUri:   redirectUri,
		state:         state,
	}
}

func DecodeAuthorizeRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		var (
			err         error
			redirectUri *url.URL
			client      Client
		)
		responseTypes := responseTypeFromString(req.FormValue("response_type"))
		clientId := req.FormValue("client_id")
		if clientId != "" {
			client, err = storage.GetClient(ctx, clientId)
			if err != nil && err != ErrClientNotFound {
				return nil, err
			}
		}

		rawRedirectUri := req.FormValue("redirect_uri")
		if len(rawRedirectUri) > 0 {
			redirectUri, err = url.Parse(rawRedirectUri)
			if err != nil || redirectUri.IsAbs() == false {
				redirectUri = nil
			}
		}

		scope := scopeFromString(req.FormValue("scope"))
		state := req.FormValue("state")

		return &authorizeRequest{
			Request: &request{
				requestedAt:     time.Now(),
				client:          client,
				requestValue:    req.Form,
				requestedScopes: scope,
			},
			responseTypes: responseTypes,
			redirectUri:   redirectUri,
			state:         state,
		}, nil
	}
}
