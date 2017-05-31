package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"
	"net/url"
	"testing"
)

func TestAuthorizeCodeHandler(t *testing.T) {
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
			error:               ErrUnsupportedResponseType,
		},
		"wrong redirect url not registerd by client": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/bar", "http://test.org/baz"},
			error:               ErrInvalidRedirectUri,
		},

		"more granted scopes than client permits": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			scope:               Scope{"foo", "bar", "baz"},
			clientScope:         Scope{"foo", "bar"},
			error:               ErrInvalidScope,
		},

		"failure generating token": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			errTokenStrat:       ErrServerError,
			error:               ErrServerError,
		},

		"failure storing token session": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			errTokenStore:       ErrServerError,
			error:               ErrServerError,
		},

		//Success
		"minimal": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			handled:             true,
		},

		"with redirect": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			redirectUri:         "http://test.com/foo",
			clientRedirectUri:   []string{"http://test.com/foo"},
			handled:             true,
		},

		"with scope": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			scope:               Scope{"foo"},
			clientScope:         Scope{"foo"},
			handled:             true,
		},

		"with state": {
			responseTypes:       ResponseTypes{CODE},
			clientResponseTypes: ResponseTypes{CODE},
			state:               "12345",
			handled:             true,
		},
	}

	for test, tc := range testcases {
		authCodeStorage := &mocks.AuthorizeCodeStorage{}
		authCodeStorage.On("CreateAuthorizeCodeSession", Anything, "test", Anything).Return(tc.errTokenStore)

		authCodeStrat := &mocks.TokenStrategy{}
		authCodeStrat.On("Generate", Anything).Return("test", "test.token", tc.errTokenStrat)

		scopeStrat := DefaultScopeStrategy
		handler := NewAuthorizeCodeHandler(authCodeStorage, authCodeStrat, scopeStrat)

		session := &mocks.Session{}

		client := &mocks.Client{}
		client.On("ClientId").Return(ClientId("1"))
		client.On("ResponseTypes").Return(tc.clientResponseTypes)
		client.On("RedirectUri").Return(tc.clientRedirectUri)
		client.On("Scope").Return(tc.clientScope)

		req := generateAuthorizeRequest(tc.responseTypes, tc.redirectUri, tc.state, tc.scope, session, client)
		resp := NewAuthorizeResponse(tc.redirectUri)

		handled, err := handler.Handle(nil, req, resp)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)
		assert.EqualValues(t, tc.handled, handled, "[%s] expected handled is %v but got %v", test, tc.handled, handled)

		if tc.error == nil && tc.handled {
			assert.EqualValues(t, "test.token", resp.GetQuery("code"), "[%s] expected code in response '%v' but got '%v'", test, "test.token", resp.GetQuery("code"))
			assert.EqualValues(t, tc.state, resp.GetQuery("state"), "[%s] expected state in response '%v' but got '%v'", test, tc.state, resp.GetQuery("state"))

			authCodeStorage.AssertNumberOfCalls(t, "CreateAuthorizeCodeSession", 1)
			authCodeStrat.AssertNumberOfCalls(t, "Generate", 1)
		}
	}
}

func generateAuthorizeRequest(responseTypes ResponseTypes, redirectUrl string, state string, grantedScopes Scope, session Session, client Client) AuthorizeRequest {
	var rurl *url.URL
	if redirectUrl != "" {
		rurl, _ = url.Parse(redirectUrl)
	}

	req := &mocks.AuthorizeRequest{}
	req.On("ResponseTypes").Return(responseTypes)
	req.On("RedirectUri").Return(rurl)
	req.On("State").Return(state)
	req.On("GrantedScopes").Return(grantedScopes)
	req.On("Session").Return(session)
	req.On("Client").Return(client)

	return req
}
