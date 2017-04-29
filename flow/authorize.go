package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"net/url"
)

type AuthorizeRequest struct {
	ResponseTypes oauth2.ResponseTypes
	ClientId      oauth2.ClientId
	RedirectUri   *url.URL
	Scope         oauth2.Scope
	State         string
	Session       oauth2.Session
}

func (_ *AuthorizeRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	responseTypes := oauth2.ResponseTypeFromString(req.FormValue("response_type"))

	//redirect url parsing and encoding
	rawRedirectUri := req.FormValue("redirect_uri")
	redirectUri, err := url.Parse(rawRedirectUri)
	if err != nil {
		return nil, oauth2.ErrInvalidRequest
	}

	clientId := req.FormValue("client_id")
	scope := oauth2.ScopeFromString(req.FormValue("scope"))
	state := req.FormValue("state")

	return &AuthorizeRequest{
		ResponseTypes: responseTypes,
		ClientId:      oauth2.ClientId(clientId),
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

func (rd *authorizeRequestWitSessionResolver) DecodeRequest(ctx context.Context, r *http.Request) (oauth2.Request, error) {
	req, err := rd.defaultRequest.DecodeRequest(ctx, r)
	if err != nil || req == nil {
		return nil, err
	}

	authReq := req.(*AuthorizeRequest)
	authReq.Session, err = rd.sessionResolver(ctx, r)
	if err != nil {
		return nil, oauth2.ErrServerError
	}
	return authReq, nil
}

func NewAuthorizeRequestDecoder(sessionResolver SessionResolverFunc) oauth2.RequestDecoder {
	return &authorizeRequestWitSessionResolver{
		defaultRequest:  &AuthorizeRequest{},
		sessionResolver: sessionResolver,
	}
}

type SessionResolverFunc func(context.Context, *http.Request) (oauth2.Session, error)

var SessionCookieId = "ssid"

// NewSessionResolver creates asimple session resolver who queries the session storage to find a session
// The session should be found trough the ssid key
func NewSessionResolver(sessions oauth2.SessionStorage) SessionResolverFunc {
	return func(ctx context.Context, r *http.Request) (oauth2.Session, error) {
		ssid, err := r.Cookie(SessionCookieId)
		if err != nil || ssid == nil {
			return nil, nil
		}
		return sessions.GetSession(oauth2.SessionId(ssid.Value))
	}
}

type AuthenticateStrategyFunc func(context.Context, *AuthorizeRequest) (oauth2.Response, error)

//NewAutenticateRedirectStrategy creates a default redirection strategy and append all the data to the url
func NewAuthenticateRedirectStrategy(uri string) AuthenticateStrategyFunc {
	baseUrl, err := url.Parse(uri)
	if err != nil {
		panic(err)
	}
	return func(ctx context.Context, r *AuthorizeRequest) (oauth2.Response, error) {
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
