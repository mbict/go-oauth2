package flow

import (
	"context"
	"github.com/mbict/go-oauth2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type ImplicitAuthorizeRequest struct {
	clientId    oauth2.ClientId
	redirectUri string
	scope       oauth2.Scope
	state       string
	session     *oauth2.Session
}

func (_ *ImplicitAuthorizeRequest) Type() string {
	return "ImplicitAuthorize"
}

func (_ *ImplicitAuthorizeRequest) DecodeRequest(ctx context.Context, req *http.Request) (oauth2.Request, error) {
	if req.FormValue("response_type") != "token" {
		return nil, nil
	}

	clientId := req.FormValue("client_id")
	redirectUri := req.FormValue("redirect_uri")
	scope := oauth2.ScopeFromString(req.FormValue("scope"))
	state := req.FormValue("state")

	return &ImplicitAuthorizeRequest{
		clientId:    oauth2.ClientId(clientId),
		redirectUri: redirectUri,
		scope:       scope,
		state:       state,
	}, nil
}

type ImplicitAuthorizeResponse struct {
	RedirectUri url.URL
	AccessToken string
	TokenType   string
	// ExpiresIn in seconds
	ExpireIn time.Duration
	Scope    oauth2.Scope
	State    string
}

func (r *ImplicitAuthorizeResponse) EncodeResponse(_ context.Context, rw http.ResponseWriter) error {
	q := r.RedirectUri.Query()
	q.Add("access_token", r.AccessToken)
	q.Add("token_type", r.TokenType)

	if r.ExpireIn.Seconds() > 0 {
		q.Add("expires_in", strconv.Itoa(int(r.ExpireIn.Seconds())))
	}

	if len(r.Scope) > 0 {
		q.Add("scope", r.Scope.String())
	}

	if r.State != "" {
		q.Add("state", r.State)
	}
	r.RedirectUri.RawQuery = q.Encode()

	rw.Header().Set("Location", r.RedirectUri.String())
	rw.WriteHeader(http.StatusFound)
	return nil
}

type ImplicitAuthorizeFlow struct {
	clients      oauth2.ClientStorage
	accessTokens oauth2.AccessTokenStorage
}

func (f *ImplicitAuthorizeFlow) Handle(ctx context.Context, req *ImplicitAuthorizeRequest) (oauth2.Response, error) {
	//find  client
	client, err := f.clients.GetClient(req.clientId)
	if err != nil {
		return nil, oauth2.ErrUnauthorizedClient
	}

	// validate redirect uri is registered
	if !hasRedirectUri(client.RedirectUri(), req.redirectUri) {
		return nil, oauth2.ErrInvalidRequest
	}

	//check if all the scopes are there
	if !client.Scope().Has(req.scope) {
		return nil, oauth2.ErrInvalidScope
	}

	//ok we create a new access token
	accessToken := ""
	expiresIn := time.Hour * 24

	resp := &AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "implicit_authorization",
		ExpiresIn:   expiresIn,
	}

	return resp, nil
}

func NewImplicitAuthorizeHandler(clients oauth2.ClientStorage, accessTokens oauth2.AccessTokenStorage) *ImplicitAuthorizeFlow {
	return &ImplicitAuthorizeFlow{
		clients:      clients,
		accessTokens: accessTokens,
	}
}
