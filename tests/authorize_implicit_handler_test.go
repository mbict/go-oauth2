package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"
	"strconv"
	"testing"
	"time"
)

func TestAuthorizeImplicitHandler(t *testing.T) {
	var testcases = map[string]struct {
		responseTypes       ResponseTypes
		clientResponseTypes ResponseTypes
		clientRedirectUri   []string
		redirectUri         string
		grantedScopes       Scope
		clientScope         Scope
		state               string
		error               error
		errTokenStrat       error
		errTokenStore       error
		handled             bool //if the handler successfully processed the request
	}{
		//Ignored
		"token response type mismatch": {
			responseTypes: ResponseTypes{CODE},
		},

		//Failures
		"unsupported response type by client": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{CODE},
			error:               ErrUnsupportedResponseType,
		},
		"wrong redirect url not registerd by client": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/bar", "http://test.org/baz"},
			error:               ErrInvalidRedirectUri,
		},

		"more granted scopes than client permits": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			grantedScopes:       Scope{"foo", "bar", "baz"},
			clientScope:         Scope{"foo", "bar"},
			error:               ErrInvalidScope,
		},

		"failure generating token": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			errTokenStrat:       ErrServerError,
			error:               ErrServerError,
		},

		"failure storing token session": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			errTokenStore:       ErrServerError,
			error:               ErrServerError,
		},

		//Success
		"minimal": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			handled:             true,
		},

		"with redirect": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			handled:             true,
		},

		"with grantedScopes": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			grantedScopes:       Scope{"foo"},
			clientScope:         Scope{"foo"},
			handled:             true,
		},

		"with state": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			state:               "12345",
			handled:             true,
		},
	}

	for test, tc := range testcases {
		t.Logf("Test case %s", test)

		accTokenStorage := &mocks.AccessTokenStorage{}
		accTokenStorage.On("CreateAccessTokenSession", Anything, "test", Anything).Return(tc.errTokenStore)

		accTokenStrat := &mocks.TokenStrategy{}
		accTokenStrat.On("GenerateAccessToken", Anything, Anything).Return("test", "test.token", tc.errTokenStrat)

		scopeStrat := DefaultScopeStrategy
		handler := NewImplicitAuthorizeHandler(accTokenStorage, accTokenStrat, scopeStrat)

		session := &mocks.Session{}
		session.On("ExpiresAt").Return(time.Now().Add(time.Hour))
		session.On("GrantedScopes").Return(tc.grantedScopes)

		client := &mocks.Client{}
		client.On("ClientId").Return(ClientId("1"))
		client.On("ResponseTypes").Return(tc.clientResponseTypes)
		client.On("RedirectUri").Return(tc.clientRedirectUri)
		client.On("Scope").Return(tc.clientScope)

		req := generateAuthorizeRequest(tc.responseTypes, tc.redirectUri, tc.state, session, client)
		resp := NewAuthorizeResponse(tc.redirectUri)

		handled, err := handler.Handle(nil, req, resp)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)
		assert.EqualValues(t, tc.handled, handled, "[%s] expected handled is %v but got %v", test, tc.handled, handled)

		if tc.error == nil && tc.handled {
			assert.EqualValues(t, "test.token", resp.GetQuery("access_token"), "[%s] expected code in response '%v' but got '%v'", test, "test.token", resp.GetQuery("access_token"))
			assert.EqualValues(t, tc.state, resp.GetQuery("state"), "[%s] expected state in response '%v' but got '%v'", test, tc.state, resp.GetQuery("state"))
			assert.EqualValues(t, tc.grantedScopes.String(), resp.GetQuery("scope"), "[%s] expected grantedScopes in response '%v' but got '%v'", test, tc.grantedScopes.String(), resp.GetQuery("scope"))

			expiresInQuery, _ := strconv.ParseFloat(resp.GetQuery("expires_in"), 64)
			assert.InDelta(t, time.Hour.Seconds(), expiresInQuery, 10, "[%s] expected expires_in in response '%d' but got '%d' with a delta of %d", test, time.Hour.Seconds(), resp.GetQuery("expires_in"), 10)

			accTokenStorage.AssertNumberOfCalls(t, "CreateAccessTokenSession", 1)
			accTokenStrat.AssertNumberOfCalls(t, "GenerateAccessToken", 1)
		}
	}
}
