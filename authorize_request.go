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

func DecodeAuthorizeRequest(storage ClientStorage) RequestDecoder {
	return func(ctx context.Context, req *http.Request) (Request, error) {
		responseTypes := responseTypeFromString(req.FormValue("response_type"))
		if len(responseTypes) == 0 {
			return nil, ErrInvalidRequest
		}

		clientId := req.FormValue("client_id")
		if clientId == "" {
			return nil, ErrInvalidRequest
		}
		client, err := storage.GetClient(ctx, clientId)
		if err == ErrClientNotFound {
			return nil, ErrUnauthorizedClient
		}
		if err != nil {
			return nil, err
		}

		//redirect url parsing and encoding
		rawRedirectUri := req.FormValue("redirect_uri")
		if len(rawRedirectUri) == 0 {
			return nil, ErrInvalidRequest
		}

		redirectUri, err := url.Parse(rawRedirectUri)
		if err != nil || redirectUri.IsAbs() == false {
			return nil, ErrInvalidRedirectUri
		}

		scope := scopeFromString(req.FormValue("scope"))
		state := req.FormValue("state")

		return &authorizeRequest{
			Request: &request{
				requestedAt: time.Now(),
				client:      client,
				//session
				requestValue:    req.Form,
				requestedScopes: scope,
				grantedScopes:   nil,
			},
			responseTypes: responseTypes,
			redirectUri:   redirectUri,
			state:         state,
		}, nil
	}
}

//func (r *AuthorizeRequest) HasSession() bool {
//	return r.Session != nil
//}
//
//type authorizeRequestWitSessionResolver struct {
//	defaultRequest  *AuthorizeRequest
//	sessionResolver SessionResolverFunc
//}
//
//func (rd *authorizeRequestWitSessionResolver) DecodeRequest(ctx context.Context, r *http.Request) (Request, error) {
//	req, err := rd.defaultRequest.DecodeRequest(ctx, r)
//	if err != nil || req == nil {
//		return nil, err
//	}
//
//	authReq := req.(*AuthorizeRequest)
//	authReq.Session, err = rd.sessionResolver(ctx, r)
//	if err != nil {
//		return nil, ErrServerError
//	}
//	return authReq, nil
//}
//
//func NewAuthorizeRequestDecoder(sessionResolver SessionResolverFunc) RequestDecoder {
//	return &authorizeRequestWitSessionResolver{
//		defaultRequest:  &AuthorizeRequest{},
//		sessionResolver: sessionResolver,
//	}
//}
