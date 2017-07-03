package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"
	"net/url"
	"testing"
	"time"
)

func TestAuthorizeCodeHandler(t *testing.T) {
	var testcases = map[string]struct {
		responseTypes       ResponseTypes
		clientResponseTypes ResponseTypes
		clientRedirectUri   []string
		omitClient          bool
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
			responseTypes: ResponseTypes{TOKEN},
		},

		//Failures
		"unsupported response type by client": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			error:               ErrUnsupportedResponseType,
		},

		"no client id provided": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{TOKEN},
			omitClient:          true,
			error:               ErrUnauthorizedClient,
		},

		"omitted redirect url": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{TOKEN},
			clientRedirectUri:   []string{"http://test.com/foo"},
			error:               ErrInvalidRedirectUri,
		},

		"wrong redirect url": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{TOKEN},
			redirectUri:         "http://bar.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			error:               ErrInvalidRedirectUri,
		},

		"more granted scopes than client permits": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			grantedScopes:       Scope{"foo", "bar", "baz"},
			clientScope:         Scope{"foo", "bar"},
			error:               ErrInvalidScope,
		},

		"failure generating token": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			errTokenStrat:       ErrServerError,
			error:               ErrServerError,
		},

		"failure storing token session": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			errTokenStore:       ErrServerError,
			error:               ErrServerError,
		},

		//Success
		"with redirect": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			handled:             true,
		},

		"with grantedScopes": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			grantedScopes:       Scope{"foo"},
			clientScope:         Scope{"foo"},
			handled:             true,
		},

		"with state": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			state:               "12345",
			handled:             true,
		},
	}

	for test, tc := range testcases {
		t.Logf("Test case %s", test)

		authCodeStorage := &mocks.AuthorizeCodeStorage{}
		authCodeStorage.On("CreateAuthorizeCodeSession", Anything, "test", Anything).Return(tc.errTokenStore)

		authCodeStrat := &mocks.TokenStrategy{}
		authCodeStrat.On("GenerateAuthorizeCode", Anything, Anything).Return("test", "test.token", tc.errTokenStrat)

		scopeStrat := DefaultScopeStrategy
		handler := NewAuthorizeCodeHandler(authCodeStorage, authCodeStrat, scopeStrat)

		session := &mocks.Session{}
		session.On("GrantedScopes").Return(tc.grantedScopes)

		var client Client
		if !tc.omitClient {
			mc := &mocks.Client{}
			mc.On("ClientId").Return(ClientId("1"))
			mc.On("ResponseTypes").Return(tc.clientResponseTypes)
			mc.On("RedirectUri").Return(tc.clientRedirectUri)
			mc.On("Scope").Return(tc.clientScope)
			client = mc
		}
		req := generateAuthorizeRequest(tc.responseTypes, tc.redirectUri, tc.state, session, client)
		resp := NewAuthorizeResponse(tc.redirectUri)

		handled, err := handler.Handle(nil, req, resp)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)
		assert.EqualValues(t, tc.handled, handled, "[%s] expected handled is %v but got %v", test, tc.handled, handled)

		if tc.error == nil && tc.handled {
			assert.EqualValues(t, "test.token", resp.GetQuery("code"), "[%s] expected code in response '%v' but got '%v'", test, "test.token", resp.GetQuery("code"))
			assert.EqualValues(t, tc.state, resp.GetQuery("state"), "[%s] expected state in response '%v' but got '%v'", test, tc.state, resp.GetQuery("state"))

			authCodeStorage.AssertNumberOfCalls(t, "CreateAuthorizeCodeSession", 1)
			authCodeStrat.AssertNumberOfCalls(t, "GenerateAuthorizeCode", 1)
		}
	}
}

func generateAuthorizeRequest(responseTypes ResponseTypes, redirectUrl string, state string, session Session, client Client) AuthorizeRequest {
	var rurl *url.URL
	if redirectUrl != "" {
		rurl, _ = url.Parse(redirectUrl)
	}
	return NewAuthorizeRequest(time.Now(), client, session, nil, nil, responseTypes, rurl, state)
}
