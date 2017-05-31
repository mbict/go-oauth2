package tests

import (
	. "github.com/mbict/go-oauth2"
	"github.com/mbict/go-oauth2/mocks"
	"github.com/stretchr/testify/assert"
	. "github.com/stretchr/testify/mock"

	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

func TestRefreshRequestDecoder(t *testing.T) {
	var testcases = map[string]struct {
		url        string
		postForm   string
		authHeader string
		ignored    bool
		error      error
		clientId   string
		scope      Scope
		token      string
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
			postForm: "grant_type=refresh_token",
			error:    ErrInvalidRequest},
		"wrong format client": {
			postForm:   "grant_type=refresh_token",
			authHeader: "wrongvalue",
			error:      ErrInvalidRequest},
		"non existing client": {
			postForm:   "grant_type=refresh_token",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("2:test")),
			error:      ErrUnauthorizedClient},
		"failing client store": {
			postForm:   "grant_type=refresh_token",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("3:test")),
			error:      ErrExternalError},
		"missing token": {
			postForm:   "grant_type=refresh_token",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidToken},

		//success
		"no scope": {
			postForm:   "grant_type=refresh_token&refresh_token=test",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			token:      "test",
			clientId:   "1"},
		"with empty scope": {
			postForm:   "grant_type=refresh_token&refresh_token=test&scope=&test=",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			token:      "test",
			clientId:   "1"},
		"with scope": {
			postForm:   "grant_type=refresh_token&refresh_token=test&scope=test",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			token:      "test",
			clientId:   "1",
			scope:      Scope{"test"}},
		"with scopes space encoded": {
			postForm:   "grant_type=refresh_token&refresh_token=test&scope=test%20abc",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			token:      "test",
			clientId:   "1",
			scope:      Scope{"test", "abc"}},
		"with scopes plus encoded": {
			postForm:   "grant_type=refresh_token&refresh_token=test&scope=test+abc",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			token:      "test",
			clientId:   "1",
			scope:      Scope{"test", "abc"}},
	}

	client := &mocks.Client{}
	client.On("ClientId").Return(ClientId("1"))

	storage := &mocks.ClientStorage{}
	storage.On("AuthenticateClient", Anything, "1", "test").Return(client, nil)
	storage.On("AuthenticateClient", Anything, "3", "test").Return(nil, ErrExternalError)
	storage.On("AuthenticateClient", Anything, Anything, Anything).Return(nil, ErrUnauthorizedClient)

	decoder := DecodeRefreshRequest(storage)

	for test, tc := range testcases {
		t.Logf("Test case %s", test)

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
			assert.IsType(t, req, &RefreshRequest{}, "[%s] expected reqest to be type of RefreshRequest but got %T", test, req)
			if ar, ok := req.(*RefreshRequest); ok == true {
				assert.EqualValues(t, tc.clientId, ar.Client().ClientId(), "[%s] expected client id '%s' but got '%s'", test, tc.clientId, ar.Client().ClientId())
				assert.EqualValues(t, r.Form.Encode(), ar.RequestValues().Encode(), "[%s] expected request values '%v' but got '%v'", test, r.Form.Encode(), ar.RequestValues().Encode())
				assert.EqualValues(t, tc.token, ar.RefreshToken(), "[%s] expected refresh token '%s' but got '%s'", test, tc.token, ar.RefreshToken())
				assert.EqualValues(t, tc.scope, ar.RequestedScopes(), "[%s] expected scope value '%s' but got '%s'", test, tc.scope, ar.RequestedScopes())
				assert.False(t, ar.RequestedAt().IsZero(), "[%s] expected requested at to be non zero but it is nil", test)
				assert.Nil(t, ar.Session(), "[%s] expected session to be nil but it is %s", test, ar.Session())
			}
		}
	}
}
