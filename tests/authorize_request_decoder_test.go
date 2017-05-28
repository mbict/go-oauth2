package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/tests/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"

	"net/http"
	"testing"
)

func TestAuthorizeRequestDecoder(t *testing.T) {
	var testcases = map[string]struct {
		url          string
		error        error
		responseType ResponseTypes
		clientId     string
		redirectUri  string
		scope        Scope
		state        string
	}{
		//Failures
		"no response type": {
			url:   "ar",
			error: ErrInvalidRequest},
		"no client id": {
			url:   "ar?response_type=code",
			error: ErrInvalidRequest},
		"failing client store": {
			url:   "ar?response_type=code&client_id=3",
			error: ErrExternalError},
		"invalid client id": {
			url:   "ar?response_type=code&client_id=2",
			error: ErrUnauthorizedClient},
		"missing redirect url": {
			url:   "ar?response_type=code&client_id=1",
			error: ErrInvalidRequest},
		"absolute redirect url": {
			url:   "ar?response_type=code&client_id=1&redirect_uri=blup",
			error: ErrInvalidRedirectUri},
		"malformed redirect url": {
			url:   "ar?response_type=code&client_id=1&redirect_uri=x%5C%24%3As%2F%3As%23",
			error: ErrInvalidRedirectUri},

		//Success
		"minimal path": {
			url:          "ar?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath",
			responseType: ResponseTypes{"code"},
			clientId:     "1",
			redirectUri:  "https://test.com/path"},
		"multiple response types plus encoded": {
			url:          "ar?response_type=code+token&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath",
			responseType: ResponseTypes{"code", "token"},
			clientId:     "1",
			redirectUri:  "https://test.com/path"},
		"multiple response types space encoded": {
			url:          "ar?response_type=code%20token&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath",
			responseType: ResponseTypes{"code", "token"},
			clientId:     "1",
			redirectUri:  "https://test.com/path"},
		"with empty scope": {
			url:          "ar?response_type=token&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath&scope=&boo=test",
			responseType: ResponseTypes{"token"},
			clientId:     "1",
			redirectUri:  "https://test.com/path"},
		"with scope": {
			url:          "ar?response_type=token&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath&scope=test",
			responseType: ResponseTypes{"token"},
			clientId:     "1",
			redirectUri:  "https://test.com/path",
			scope:        Scope{"test"}},
		"with scopes space encoded": {
			url:          "ar?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath&scope=test%20abc",
			responseType: ResponseTypes{"code"},
			clientId:     "1",
			redirectUri:  "https://test.com/path",
			scope:        Scope{"test", "abc"}},
		"with scopes plus encoded": {
			url:          "ar?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath&scope=test+abc",
			responseType: ResponseTypes{"code"},
			clientId:     "1",
			redirectUri:  "https://test.com/path",
			scope:        Scope{"test", "abc"}},
		"with state": {
			url:          "ar?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Ftest.com%2Fpath&state=1234",
			responseType: ResponseTypes{"code"},
			clientId:     "1",
			redirectUri:  "https://test.com/path",
			state:        "1234"},
	}

	client := &mocks.Client{}
	client.On("ClientId").Return(ClientId("1"))

	storage := &mocks.ClientStorage{}
	storage.On("GetClient", Anything, "1").Return(client, nil)
	storage.On("GetClient", Anything, "3").Return(nil, ErrExternalError)
	storage.On("GetClient", Anything, Anything).Return(nil, ErrClientNotFound)
	decoder := DecodeAuthorizeRequest(storage)

	for test, tc := range testcases {
		r, _ := http.NewRequest("GET", tc.url, nil)
		req, err := decoder(nil, r)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)

		//failure path
		if tc.error != nil {
			assert.Nil(t, req, "[%s] expected nil result but got %v", test, req)
		}

		//success path
		if tc.error == nil {
			assert.Implements(t, (*AuthorizeRequest)(nil), req, "[%s] expected reqest to be an implementation of AuthorizeRequest but got %T", test, req)
			if ar, ok := req.(AuthorizeRequest); ok == true {
				assert.EqualValues(t, tc.responseType, ar.ResponseTypes(), "[%s] expected response type '%s' but got '%s'", test, tc.responseType, ar.ResponseTypes())
				assert.EqualValues(t, tc.clientId, ar.Client().ClientId(), "[%s] expected client id '%s' but got '%s'", test, tc.clientId, ar.Client().ClientId())
				assert.EqualValues(t, tc.redirectUri, ar.RedirectUri().String(), "[%s] redirect uri '%s' but got '%s'", test, tc.redirectUri, ar.RedirectUri())
				assert.EqualValues(t, tc.scope, ar.RequestedScopes(), "[%s] expected scope value '%s' but got '%s'", test, tc.scope, ar.RequestedScopes())
				assert.EqualValues(t, tc.state, ar.State(), "[%s] expected state value '%s' but got '%s'", test, tc.state, ar.State())
				assert.EqualValues(t, r.Form.Encode(), ar.RequestValues().Encode(), "[%s] expected request values '%v' but got '%v'", test, r.Form.Encode(), ar.RequestValues().Encode())
				assert.False(t, ar.RequestedAt().IsZero(), "[%s] expected requested at to be non zero but it is", test)
			}
		}
	}
}
