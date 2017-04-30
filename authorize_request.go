package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

type AuthorizeRequest struct {
	ResponseTypes ResponseTypes
	ClientId      ClientId
	RedirectUri   *url.URL
	Scope         Scope
	State         string
	Session       Session
}

func (_ *AuthorizeRequest) DecodeRequest(ctx context.Context, req *http.Request) (Request, error) {
	responseTypes := ResponseTypeFromString(req.FormValue("response_type"))

	//redirect url parsing and encoding
	rawRedirectUri := req.FormValue("redirect_uri")
	redirectUri, err := url.Parse(rawRedirectUri)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	clientId := req.FormValue("client_id")
	scope := ScopeFromString(req.FormValue("scope"))
	state := req.FormValue("state")

	return &AuthorizeRequest{
		ResponseTypes: responseTypes,
		ClientId:      ClientId(clientId),
		RedirectUri:   redirectUri,
		Scope:         scope,
		State:         state,
	}, nil
}

func (r *AuthorizeRequest) HasSession() bool {
	return r.Session != nil
}

type authorizeRequestWitSessionResolver struct {
	defaultRequest  *AuthorizeRequest
	sessionResolver SessionResolverFunc
}

func (rd *authorizeRequestWitSessionResolver) DecodeRequest(ctx context.Context, r *http.Request) (Request, error) {
	req, err := rd.defaultRequest.DecodeRequest(ctx, r)
	if err != nil || req == nil {
		return nil, err
	}

	authReq := req.(*AuthorizeRequest)
	authReq.Session, err = rd.sessionResolver(ctx, r)
	if err != nil {
		return nil, ErrServerError
	}
	return authReq, nil
}

func NewAuthorizeRequestDecoder(sessionResolver SessionResolverFunc) RequestDecoder {
	return &authorizeRequestWitSessionResolver{
		defaultRequest:  &AuthorizeRequest{},
		sessionResolver: sessionResolver,
	}
}
