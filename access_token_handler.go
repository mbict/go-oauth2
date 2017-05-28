package oauth2

import (
	"context"
)

type AccessTokenHandler struct {
	authorizeCodeStorage  AuthorizeCodeStorage
	accessTokenStorage    AccessTokenStorage
	refreshTokenStorage   RefreshTokenStorage
	authorizeCodeStrategy TokenStrategy
	accessTokenStrategy   TokenStrategy
	refreshTokenStrategy  TokenStrategy
}

func (h *AccessTokenHandler) Handle(ctx context.Context, req *AccessTokenRequest) (Response, error) {
	//validate signature
	/*	signature, err := h.authorizeCodeStrategy.Signature(req.Code())
		if err != nil {
			return nil, ErrInvalidSignature
		}

		//check if code session exists for this client id
		code, err := h.codes.GetAuthorizeCodeSession(ctx, signature)
		if err != nil || code.ClientId() != req.Client().ClientId() {
			return nil, ErrUnauthorizedClient
		}

		//check if the redirect uri matches the request
		if code.redirectUri() != req.redirectUri().String() {
			return nil, ErrInvalidRequest
		}

		//ok we remove the code token
		_, err = h.codes.DeleteAuthorizeCodeSession(ctx, signature)

		//create access token
		//accessTokenSignature, accessToken, err := h.accessTokenStrategy.Generate( )
		//err := h.accessTokenStorage.CreateAccessTokenSession(accessTokenSignature)

		//ok we create new refresh token

		//create new access token

		//refreshTokenSignature, refreshToken, err := h.refreshTokenStrategy.Generate()
		expiresIn := time.Hour * 24

		resp := &AccessTokenResponse{
			//AccessToken:  accessToken,
			TokenType: "resource_owner",
			ExpiresIn: expiresIn,
			//RefreshToken: refreshToken,
		}

		return resp, nil
	*/
	return nil, nil
}

func NewAccessTokenHandler(
	authorizeCodeStorage AuthorizeCodeStorage,
	accessTokenStorage AccessTokenStorage,
	refreshTokenStorage RefreshTokenStorage,
	authorizeCodeStrategy TokenStrategy,
	accessTokenStrategy TokenStrategy,
	refreshTokenStrategy TokenStrategy) *AccessTokenHandler {
	return &AccessTokenHandler{
		authorizeCodeStorage:  authorizeCodeStorage,
		accessTokenStorage:    accessTokenStorage,
		refreshTokenStorage:   refreshTokenStorage,
		authorizeCodeStrategy: authorizeCodeStrategy,
		accessTokenStrategy:   accessTokenStrategy,
		refreshTokenStrategy:  refreshTokenStrategy,
	}
}
