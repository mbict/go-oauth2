package oauth2

import (
	"fmt"
)

var (
	// ErrSessionExpired is used when a session is expired
	ErrSessionExpired = NewError("session expired")

	// ErrInvalidSignature is used when a malformed signature is used
	ErrInvalidSignature = NewError("invalid signature")

	// ErrInvalidToken is used when a request does not provide a token
	ErrInvalidToken = NewError("invalid token")

	// ErrInvalidToken is used when a request does not provide a token
	ErrInvalidCode = NewError("invalid code")

	// ErrAuthenticateFailed is used when an user could not be authenticated with username and password.
	ErrAuthenticateFailed = NewError("authenticate failed")

	// The request is missing a required parameter, includes an
	// invalid parameter value, includes a parameter more than
	// once, or is otherwise malformed.
	ErrInvalidRequest = NewError("invalid_request")

	// The client is not authorized to request an authorization
	// code using this method.
	ErrUnauthorizedClient = NewError("unauthorized_client")

	// The resource owner or authorization server denied the
	// request.
	ErrAccessDenied = NewError("access_denied")

	// The authorization server does not support obtaining an
	// authorization code using this method.
	ErrUnsupportedResponseType = NewError("unsupported_response_type")

	// The authorization server does not support obtaining an
	// access token using this method.
	ErrUnsupportedGrantType = NewError("unsupported_grant_type")

	// The requested scope is invalid, unknown, or malformed.
	ErrInvalidScope = NewError("invalid_scope")

	// The authorization server encountered an unexpected
	// condition that prevented it from fulfilling the request.
	// (This err code is needed because a 500 Internal Server
	// OAuthError HTTP status code cannot be returned to the client
	// via an HTTP redirect.)
	ErrServerError = NewError("server_error")

	// The authorization server is currently unable to handle
	// the request due to a temporary overloading or maintenance
	// of the server.  (This err code is needed because a 503
	// Service Unavailable HTTP status code cannot be returned
	// to the client via an HTTP redirect.)
	ErrTemporarilyUnavailable = NewError("temporarily_unavailable")

	// Thee authorization server does not support
	// the revocation of the presented token type.
	ErrUnsupportedTokenType = NewError("unsupported_token_type")

	ErrInvalidRedirectUri = NewError("invalid_redirect_uri")
)

type OAuthError interface {
	error
	RFC6749() *RFC6749Error
}

type oauthError struct {
	error
}

func (e *oauthError) RFC6749() *RFC6749Error {
	return errorToRFC6749Error(e)
}

func NewError(e interface{}) OAuthError {
	var err error
	switch e := e.(type) {
	case error:
		err = e
	default:
		err = fmt.Errorf("%v", e)
	}

	return &oauthError{
		error: err,
	}
}
