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

func TestAccessTokenRequestDecoder(t *testing.T) {
	var testcases = map[string]struct {
		url         string
		postForm    string
		authHeader  string
		ignored     bool
		error       error
		code        string
		clientId    string
		redirectUri string
	}{
		//ignored special case
		"no body, should ignore": {
			postForm: "",
			ignored:  true},
		"wrong grant_type, ignore": {
			postForm: "grant_type=password",
			ignored:  true},

		//failures
		"missing client credentials": {
			postForm: "grant_type=authorization_code",
			error:    ErrInvalidRequest},
		"wrong format client": {
			postForm:   "grant_type=authorization_code",
			authHeader: "wrongvalue",
			error:      ErrInvalidRequest},
		"non existing client": {
			postForm:   "grant_type=authorization_code",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("2:test")),
			error:      ErrUnauthorizedClient},
		"failing client store": {
			postForm:   "grant_type=authorization_code",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("3:test")),
			error:      ErrExternalError},
		"missing redirect url": {
			postForm:   "grant_type=authorization_code",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidRequest},
		"absolute redirect url": {
			postForm:   "grant_type=authorization_code&redirect_uri=blup",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidRedirectUri},
		"malformed redirect url": {
			postForm:   "grant_type=authorization_code&redirect_uri=x%5C%24%3As%2F%3As%23",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidRedirectUri},
		"missing code": {
			postForm:   "grant_type=authorization_code&redirect_uri=https%3A%2F%2Ftest.com%2Fpath",
			authHeader: base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			error:      ErrInvalidCode},

		//success
		"passing request": {
			postForm:    "grant_type=authorization_code&code=test&redirect_uri=https%3A%2F%2Ftest.com%2Fpath",
			authHeader:  base64.RawURLEncoding.EncodeToString([]byte("1:test")),
			code:        "test",
			clientId:    "1",
			redirectUri: "https://test.com/path"},
	}

	client := &mocks.Client{}
	client.On("ClientId").Return(ClientId("1"))

	storage := &mocks.ClientStorage{}
	storage.On("AuthenticateClient", Anything, "1", "test").Return(client, nil)
	storage.On("AuthenticateClient", Anything, "3", "test").Return(nil, ErrExternalError)
	storage.On("AuthenticateClient", Anything, Anything, Anything).Return(nil, ErrUnauthorizedClient)
	decoder := DecodeAccessTokenRequest(storage)

	for test, tc := range testcases {
		r, _ := http.NewRequest("POST", tc.url, nil)
		r.PostForm, _ = url.ParseQuery(tc.postForm)
		if tc.authHeader != "" {
			r.Header.Add("Authorization", "Basic "+tc.authHeader)
		}
		req, err := decoder(nil, r)

		assert.EqualValues(t, tc.error, err, "[%s] expected err %v as error but got %v", test, tc.error, err)

		if tc.ignored == true || tc.error != nil {
			assert.Nil(t, req, "[%s] expected nil result but got %v", test, req)
			continue
		}

		//success path
		if tc.error == nil {
			assert.Implements(t, (*AccessTokenRequest)(nil), req, "[%s] expected request to be type of AccessTokenRequest but got %T", test, req)
			if ar, ok := req.(AccessTokenRequest); ok == true {
				assert.EqualValues(t, tc.clientId, ar.Client().ClientId(), "[%s] expected client id '%s' but got '%s'", test, tc.clientId, ar.Client().ClientId())
				assert.EqualValues(t, tc.code, ar.Code(), "[%s] expected code '%s' but got '%s'", test, tc.code, ar.Code())
				assert.EqualValues(t, tc.redirectUri, ar.RedirectUri().String(), "[%s] redirect uri '%s' but got '%s'", test, tc.redirectUri, ar.RedirectUri().String())
				assert.EqualValues(t, r.Form.Encode(), ar.RequestValues().Encode(), "[%s] expected request values '%v' but got '%v'", test, r.Form.Encode(), ar.RequestValues().Encode())
				assert.False(t, ar.RequestedAt().IsZero(), "[%s] expected requested at to be non zero but it is", test)
			}
		}
	}
}
