package oauth2

import (
	"context"
	"time"
)

type AccessTokenHandler struct {
	authorizeCodeStorage  AuthorizeCodeStorage
	accessTokenStorage    AccessTokenStorage
	refreshTokenStorage   RefreshTokenStorage
	authorizeCodeStrategy TokenStrategy
	accessTokenStrategy   TokenStrategy
	refreshTokenStrategy  TokenStrategy
	refreshTokenScope     string
}

func (h *AccessTokenHandler) Handle(ctx context.Context, req AccessTokenRequest) (Response, error) {

	if !req.Client().GrantTypes().Contains(AUTHORIZATION_CODE) {
		return nil, ErrUnsupportedGrantType
	}

	//validate signature
	signature, err := h.authorizeCodeStrategy.Signature(req.Code())
	if err != nil {
		return nil, err
	}

	reqSession, err := h.authorizeCodeStorage.GetAuthorizeCodeSession(ctx, signature)
	if err != nil {
		return nil, err
	}

	// session must be issued for this client
	if reqSession.Client().ClientId() != req.Client().ClientId() {
		return nil, ErrUnauthorizedClient
	}

	// session cannot be expired
	if reqSession.Session().ExpiresAt().After(time.Now()) == false {
		return nil, ErrSessionExpired
	}

	// validate redirect uri is registered for this client
	if (req.RedirectUri() == nil) != (reqSession.RedirectUri() == nil) ||
		(req.RedirectUri() != nil && reqSession.RedirectUri().String() != req.RedirectUri().String()) {
		return nil, ErrInvalidRedirectUri
	}

	//remove authorize code
	_, err = h.authorizeCodeStorage.DeleteAuthorizeCodeSession(ctx, signature)
	if err != nil {
		return nil, err
	}

	//create
	accessSignature, accessToken, err := h.accessTokenStrategy.Generate(reqSession)
	if err != nil {
		return nil, err
	}

	err = h.accessTokenStorage.CreateAccessTokenSession(ctx, accessSignature, req)
	if err != nil {
		return nil, err
	}

	//check if we need to create a refresh token,
	//only if we have a refresh token strategy, and we have a scope granted that allows refresh tokens
	refreshToken := ""
	createRefreshToken := h.refreshTokenScope == "" || req.GrantedScopes().Has(Scope{h.refreshTokenScope})

	if h.refreshTokenStrategy != nil && createRefreshToken == true {
		signature, refreshToken, err = h.refreshTokenStrategy.Generate(reqSession)
		if err != nil {
			return nil, err
		}

		err = h.refreshTokenStorage.CreateRefreshTokenSession(ctx, signature, req)
		if err != nil {
			return nil, err
		}
	}

	return &accessTokenResponse{
		accessToken:  accessToken,
		tokenType:    "Bearer",
		expiresIn:    reqSession.Session().ExpiresAt().Sub(time.Now()),
		refreshToken: refreshToken,
		data:         make(map[string]interface{}),
	}, nil
}

func NewAccessTokenHandler(
	authorizeCodeStorage AuthorizeCodeStorage, accessTokenStorage AccessTokenStorage, refreshTokenStorage RefreshTokenStorage,
	authorizeCodeStrategy TokenStrategy, accessTokenStrategy TokenStrategy, refreshTokenStrategy TokenStrategy,
	refreshTokenScope string) *AccessTokenHandler {
	return &AccessTokenHandler{
		authorizeCodeStorage:  authorizeCodeStorage,
		accessTokenStorage:    accessTokenStorage,
		refreshTokenStorage:   refreshTokenStorage,
		authorizeCodeStrategy: authorizeCodeStrategy,
		accessTokenStrategy:   accessTokenStrategy,
		refreshTokenStrategy:  refreshTokenStrategy,
		refreshTokenScope:     refreshTokenScope,
	}
}
