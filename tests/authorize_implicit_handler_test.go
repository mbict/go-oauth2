package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/tests/mocks"
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
		scope               Scope
		clientScope         Scope
		state               string
		error               error
		errTokenStrat       error
		errTokenStore       error
	}{
		//Failures
		"token response type mismatch": {
			responseTypes: ResponseTypes{CODE},
			error:         ErrInvalidRequest,
		},
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
			scope:               Scope{"foo", "bar", "baz"},
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
		},

		"with redirect": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
		},

		"with scope": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			scope:               Scope{"foo"},
			clientScope:         Scope{"foo"},
		},

		"with state": {
			responseTypes:       ResponseTypes{TOKEN},
			clientResponseTypes: ResponseTypes{TOKEN},
			state:               "12345",
		},
	}

	for test, tc := range testcases {
		accCodeStorage := &mocks.AccessTokenStorage{}
		accCodeStorage.On("CreateAccessTokenSession", Anything, "test", Anything).Return(tc.errTokenStore)

		authCodeStrat := &mocks.TokenStrategy{}
		authCodeStrat.On("Generate", Anything).Return("test", "test.token", tc.errTokenStrat)

		scopeStrat := DefaultScopeStrategy
		handler := NewImplicitAuthorizeHandler(accCodeStorage, authCodeStrat, scopeStrat)

		session := &mocks.Session{}
		session.On("ExpiresAt").Return(time.Now().Add(time.Hour))

		client := &mocks.Client{}
		client.On("ClientId").Return(ClientId("1"))
		client.On("ResponseTypes").Return(tc.clientResponseTypes)
		client.On("RedirectUri").Return(tc.clientRedirectUri)
		client.On("Scope").Return(tc.clientScope)

		req := generateAuthorizeRequest(tc.responseTypes, tc.redirectUri, tc.state, tc.scope, session, client)
		resp := NewAuthorizeResponse(tc.redirectUri)

		err := handler.Handle(nil, req, resp)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)

		if tc.error == nil {
			assert.EqualValues(t, "test.token", resp.GetQuery("access_token"), "[%s] expected code in response '%v' but got '%v'", test, "test.token", resp.GetQuery("access_token"))
			assert.EqualValues(t, tc.state, resp.GetQuery("state"), "[%s] expected state in response '%v' but got '%v'", test, tc.state, resp.GetQuery("state"))
			assert.EqualValues(t, tc.scope.String(), resp.GetQuery("scope"), "[%s] expected scope in response '%v' but got '%v'", test, tc.scope.String(), resp.GetQuery("scope"))

			expiresInQuery, _ := strconv.ParseFloat(resp.GetQuery("expires_in"), 64)
			assert.InDelta(t, time.Hour.Seconds(), expiresInQuery, 10, "[%s] expected expires_in in response '%d' but got '%d' with a delta of %d", test, time.Hour.Seconds(), resp.GetQuery("expires_in"), 10)

			accCodeStorage.AssertNumberOfCalls(t, "CreateAccessTokenSession", 1)
			authCodeStrat.AssertNumberOfCalls(t, "Generate", 1)
		}
	}

}