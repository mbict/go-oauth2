package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/tests/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"

	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

func TestResourceOwnerRequestDecoder(t *testing.T) {
	var testcases = map[string]struct {
		url        string
		postForm   string
		authHeader string
		ignored    bool
		error      error
		clientId   string
		scope      Scope
	}{
		//ignored special case
		"no body, should ignore": {
			postForm: "",
			ignored:  true},
		"wrong grant_type, ignore": {
			postForm: "grant_type=client_credentials",
			ignored:  true},

		//failures
		"missing client credentials": {
			postForm: "grant_type=password",
			error:    ErrInvalidRequest},
		"wrong format client": {
			postForm:   "grant_type=password",
			authHeader: "wrongvalue",
			error:      ErrInvalidRequest},
		"non existing client": {
			postForm:   "grant_type=password",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("2:test")),
			error:      ErrUnauthorizedClient},
		"failing client store": {
			postForm:   "grant_type=password",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("3:test")),
			error:      ErrExternalError},
		"missing resource owner credentials": {
			postForm:   "grant_type=password",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidRequest},
		"unable to authenticate resource owner": {
			postForm:   "grant_type=password&username=nothere&password=pass",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrAuthenticateFailed},
		"failing user store": {
			postForm:   "grant_type=password&username=failure&password=pass",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrExternalError},

		//success
		"no scope": {
			postForm:   "grant_type=password&username=test&password=pass",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			clientId:   "1"},
		"with empty scope": {
			postForm:   "grant_type=password&username=test&password=pass&scope=&test=",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			clientId:   "1"},
		"with scope": {
			postForm:   "grant_type=password&username=test&password=pass&scope=test",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			clientId:   "1",
			scope:      Scope{"test"}},
		"with scopes space encoded": {
			postForm:   "grant_type=password&username=test&password=pass&scope=test%20abc",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			clientId:   "1",
			scope:      Scope{"test", "abc"}},
		"with scopes plus encoded": {
			postForm:   "grant_type=password&username=test&password=pass&scope=test+abc",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			clientId:   "1",
			scope:      Scope{"test", "abc"}},
	}

	client := &mocks.Client{}
	client.On("ClientId").Return(ClientId("1"))

	clientStorage := &mocks.ClientStorage{}
	clientStorage.On("AuthenticateClient", Anything, "1", "test").Return(client, nil)
	clientStorage.On("AuthenticateClient", Anything, "3", "test").Return(nil, ErrExternalError)
	clientStorage.On("AuthenticateClient", Anything, Anything, Anything).Return(nil, ErrUnauthorizedClient)

	userStorage := &mocks.UserStorage{}
	userStorage.On("AuthenticateUser", Anything, "test", "pass").Return("test", nil)
	userStorage.On("AuthenticateUser", Anything, "failure", "pass").Return("", ErrExternalError)
	userStorage.On("AuthenticateUser", Anything, Anything, Anything).Return("", ErrAuthenticateFailed)

	decoder := DecodeResourceOwnerRequest(clientStorage, userStorage)

	for test, tc := range testcases {
		r, _ := http.NewRequest("POST", tc.url, nil)
		r.PostForm, _ = url.ParseQuery(tc.postForm)
		if tc.authHeader != "" {
			r.Header.Add("Authorization", "Basic "+tc.authHeader)
		}
		req, err := decoder(nil, r)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)

		// ignores and failure paths
		if tc.ignored == true || tc.error != nil {
			assert.Nil(t, req, "[%s] expected nil result but got %v", test, req)
			continue
		}

		//success path
		if tc.error == nil {
			assert.IsType(t, req, &ResourceOwnerRequest{}, "[%s] expected reqest to be type of ResourceOwnerRequest but got %T", test, req)
			if ar, ok := req.(*ResourceOwnerRequest); ok == true {
				assert.EqualValues(t, tc.clientId, ar.Client().ClientId(), "[%s] expected client id '%s' but got '%s'", test, tc.clientId, ar.Client().ClientId())
				assert.EqualValues(t, r.Form.Encode(), ar.RequestValues().Encode(), "[%s] expected request values '%v' but got '%v'", test, r.Form.Encode(), ar.RequestValues().Encode())
				assert.EqualValues(t, tc.scope, ar.RequestedScopes(), "[%s] expected scope value '%s' but got '%s'", test, tc.scope, ar.RequestedScopes())
				assert.False(t, ar.RequestedAt().IsZero(), "[%s] expected requested at to be non zero but it is nil", test)
				if assert.NotNil(t, ar.Session(), "[%s] expected session not to be nil but it is nil", test) {
					assert.EqualValues(t, "test", ar.Session().UserId(), "[%s] expected session user id to be '%v' nil but it is '%v'", test, "test", ar.Session().UserId())
				}
			}
		}
	}
}
