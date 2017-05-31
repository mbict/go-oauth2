package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/tests/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"
	"net/url"
	"testing"
	"time"
)

func TestAccessTokenHandler(t *testing.T) {
	defaultExpireTime := time.Now().Add(time.Minute * 60)
	defaultGrantTypes := GrantTypes{AUTHORIZATION_CODE}
	var testcases = map[string]struct {
		code                   string     //code is the authorize code
		errAuthStrat           error      //error returned by authorize token signature check
		errAuthStore           error      //error returned by authorize store when fetching the request
		errAuthStoreDelete     error      //error returned by authorize store when deleting the request
		errAccStrat            error      //error returned by access strategy token generation
		errAccStore            error      //error returned by access store when perist session
		errRefrStrat           error      //error returned by refresh strategy token generation
		errRefrStore           error      //error returned by refresh store when persist session
		sessionExpiresAt       time.Time  //the expire time of the authorize session request
		sessionIssuedForClient ClientId   //client id the authorize code request is issued
		clientGrantTypes       GrantTypes //grantTypes supported by client
		sessionRedirectUri     string     //redirect uri used in authorize code session
		redirectUri            string     //redirect uri used in request
		refreshTokenScope      string     //name of scope to enable refresh token creation
		refreshTokenEnabled    bool       //refresh token generation enabled by providing a token strategy
		scope                  Scope      //granted scope
		error                  error      //expected error
		token                  string     //expected token
		refreshToken           string     //expected refresh token
	}{
		//Failures
		"unsupported granttype": {
			clientGrantTypes: GrantTypes{PASSWORD},
			code:             "invalid.token",
			error:            ErrUnsupportedGrantType,
		},
		"invalid token": {
			clientGrantTypes: defaultGrantTypes,
			code:             "invalid.token",
			error:            ErrInvalidToken,
		},
		"signature code not found": {
			clientGrantTypes: defaultGrantTypes,
			code:             "notfound.token",
			errAuthStore:     ErrTokenNotFound,
			error:            ErrTokenNotFound,
		},
		"signature get code storage fails": {
			clientGrantTypes: defaultGrantTypes,
			code:             "storagefail.token",
			errAuthStore:     ErrServerError,
			error:            ErrServerError,
		},

		"issued for other client id": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "2",
			code:  "ok.token",
			error: ErrUnauthorizedClient,
		},
		"expired session (1 hour overdue)": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:             "ok.token",
			sessionExpiresAt: time.Now().Add(-(time.Minute * 60)),
			error:            ErrSessionExpired,
		},
		"redirect url mismatch request": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:               "ok.token",
			sessionExpiresAt:   defaultExpireTime,
			redirectUri:        "http://test.com/foo",
			sessionRedirectUri: "http://foo.bar/baz",
			error:              ErrInvalidRedirectUri,
		},
		"redirect url not used in code request": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:             "ok.token",
			sessionExpiresAt: defaultExpireTime,
			redirectUri:      "http://test.com/foo",
			error:            ErrInvalidRedirectUri,
		},
		"redirect url missing in request": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:               "ok.token",
			sessionExpiresAt:   defaultExpireTime,
			sessionRedirectUri: "http://foo.bar/baz",
			error:              ErrInvalidRedirectUri,
		},
		"signature remove failed": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:               "failremove.token",
			sessionExpiresAt:   defaultExpireTime,
			errAuthStoreDelete: ErrServerError,
			error:              ErrServerError,
		},
		"failure generating access token": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:             "ok.token",
			sessionExpiresAt: defaultExpireTime,
			errAccStrat:      ErrServerError,
			error:            ErrServerError,
		},
		"failure storing access token": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:             "ok.token",
			sessionExpiresAt: defaultExpireTime,
			errAccStrat:      ErrServerError,
			error:            ErrServerError,
		},
		"failure generating refresh token": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:                "ok.token",
			sessionExpiresAt:    defaultExpireTime,
			refreshTokenEnabled: true,
			errRefrStrat:        ErrServerError,
			error:               ErrServerError,
		},
		"failure storing refresh token": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:                "ok.token",
			sessionExpiresAt:    defaultExpireTime,
			refreshTokenEnabled: true,
			errRefrStore:        ErrServerError,
			error:               ErrServerError,
		},

		//Success
		"without refresh token strategy (disabled)": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:             "ok.token",
			sessionExpiresAt: defaultExpireTime,
			token:            "access.token",
		},
		"with matching redirect uri": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:               "ok.token",
			sessionExpiresAt:   defaultExpireTime,
			redirectUri:        "http://test.com/foo",
			sessionRedirectUri: "http://test.com/foo",
			token:              "access.token",
		},
		"always issue refresh token (empty scope)": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:                "ok.token",
			sessionExpiresAt:    defaultExpireTime,
			refreshTokenEnabled: true,
			refreshTokenScope:   "",
			token:               "access.token",
			refreshToken:        "refresh.token",
		},
		"no refresh token scope granted (offline scope)": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:                "ok.token",
			sessionExpiresAt:    defaultExpireTime,
			refreshTokenEnabled: true,
			refreshTokenScope:   "offline",
			scope:               Scope{"foo"},
			token:               "access.token",
		},
		"with refresh token scope granted (offline scope)": {
			clientGrantTypes:       defaultGrantTypes,
			sessionIssuedForClient: "1",
			code:                "ok.token",
			sessionExpiresAt:    defaultExpireTime,
			refreshTokenEnabled: true,
			scope:               Scope{"offline"},
			refreshTokenScope:   "offline",
			token:               "access.token",
			refreshToken:        "refresh.token",
		},
	}

	for test, tc := range testcases {
		authSession := &mocks.Session{}
		authSession.On("ExpiresAt").Return(tc.sessionExpiresAt)

		authClient := &mocks.Client{}
		authClient.On("ClientId").Return(tc.sessionIssuedForClient)

		reqSession := generateAuthorizeRequest(ResponseTypes{AUTHORIZATION_CODE}, tc.sessionRedirectUri, "xxx", Scope{}, authSession, authClient)

		authCodeStorage := &mocks.AuthorizeCodeStorage{}
		authCodeStorage.On("GetAuthorizeCodeSession", Anything, Anything).Return(reqSession, tc.errAuthStore)
		authCodeStorage.On("DeleteAuthorizeCodeSession", Anything, Anything).Return(true, tc.errAuthStoreDelete)

		authCodeStrat := &mocks.TokenStrategy{}
		authCodeStrat.On("Signature", "invalid.token").Return("", ErrInvalidToken)
		authCodeStrat.On("Signature", Anything).Return(func(in string) string { return in }, nil)

		accTokenStorage := &mocks.AccessTokenStorage{}
		accTokenStorage.On("CreateAccessTokenSession", Anything, Anything, Anything).Return(tc.errAccStore)

		accTokenStrat := &mocks.TokenStrategy{}
		accTokenStrat.On("Generate", Anything).Return("access", "access.token", tc.errAccStrat)

		refreshTokenStorage := &mocks.RefreshTokenStorage{}
		refreshTokenStorage.On("CreateRefreshTokenSession", Anything, Anything, Anything).Return(tc.errRefrStore)

		//when no refresh token need to be generated we omit the token strategy
		var refreshTokenStrat TokenStrategy = nil
		if tc.refreshTokenEnabled == true {
			tokenMock := &mocks.TokenStrategy{}
			tokenMock.On("Generate", Anything).Return("refresh", "refresh.token", tc.errRefrStrat)
			refreshTokenStrat = tokenMock
		}

		handler := NewAccessTokenHandler(
			authCodeStorage, accTokenStorage, refreshTokenStorage,
			authCodeStrat, accTokenStrat, refreshTokenStrat,
			tc.refreshTokenScope,
		)

		session := &mocks.Session{}
		session.On("ExpiresAt").Return(time.Now().Add(time.Hour))

		client := &mocks.Client{}
		client.On("ClientId").Return(ClientId("1"))
		client.On("GrantTypes").Return(tc.clientGrantTypes)

		req := generateAccessTokenRequest(tc.code, tc.redirectUri, tc.scope, session, client)

		resp, err := handler.Handle(nil, req)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)
		if tc.error == nil {
			assert.Implements(t, (*AccessTokenResponse)(nil), resp, "[%s] expected request to be type of AccessTokenResponse but got %T", test, resp)
			if aresp, ok := resp.(AccessTokenResponse); ok == true {
				assert.EqualValues(t, tc.token, aresp.AccessToken(), "[%s] expected access token in response '%v' but got '%v'", test, tc.token, aresp.AccessToken())
				assert.EqualValues(t, tc.refreshToken, aresp.RefreshToken(), "[%s] expected refresh token in response '%v' but got '%v'", test, tc.refreshToken, aresp.RefreshToken())
				assert.EqualValues(t, "Bearer", aresp.TokenType(), "[%s] expected token type in response '%v' but got '%v'", test, "Bearer", aresp.TokenType())
				assert.InDelta(t, time.Hour.Seconds(), aresp.ExpiresIn().Seconds(), 10, "[%s] expected expires_in in response '%d' but got '%d' with a delta of %d", test, time.Hour.Seconds(), aresp.ExpiresIn().Seconds(), 10)
			}
		}
	}
}

func generateAccessTokenRequest(code string, redirectUrl string, grantedScopes Scope, session Session, client Client) AccessTokenRequest {
	var rurl *url.URL
	if redirectUrl != "" {
		rurl, _ = url.Parse(redirectUrl)
	}

	req := &mocks.AccessTokenRequest{}
	req.On("Code").Return(code)
	req.On("RedirectUri").Return(rurl)
	req.On("GrantedScopes").Return(grantedScopes)
	req.On("Session").Return(session)
	req.On("Client").Return(client)

	return req
}
