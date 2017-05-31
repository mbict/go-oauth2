package oauth2

import "errors"

var (
	// ErrSessionExpired is used when a session is expired
	ErrSessionExpired = errors.New("session expired")

	// ErrInvalidSignature is used when a malformed signature is used
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidToken is used when a request does not provide a token
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidToken is used when a request does not provide a token
	ErrInvalidCode = errors.New("invalid code")

	// ErrAuthenticateFailed is used when an user could not be authenticated with username and password.
	ErrAuthenticateFailed = errors.New("authenticate failed")

	// The request is missing a required parameter, includes an
	// invalid parameter value, includes a parameter more than
	// once, or is otherwise malformed.
	ErrInvalidRequest = errors.New("invalid_request")

	// The client is not authorized to request an authorization
	// code using this method.
	ErrUnauthorizedClient = errors.New("unauthorized_client")

	// The resource owner or authorization server denied the
	// request.
	ErrAccessDenied = errors.New("access_denied")

	// The authorization server does not support obtaining an
	// authorization code using this method.
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")

	// The authorization server does not support obtaining an
	// access token using this method.
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")

	// The requested scope is invalid, unknown, or malformed.
	ErrInvalidScope = errors.New("invalid_scope")

	// The authorization server encountered an unexpected
	// condition that prevented it from fulfilling the request.
	// (This error code is needed because a 500 Internal Server
	// Error HTTP status code cannot be returned to the client
	// via an HTTP redirect.)
	ErrServerError = errors.New("server_error")

	// The authorization server is currently unable to handle
	// the request due to a temporary overloading or maintenance
	// of the server.  (This error code is needed because a 503
	// Service Unavailable HTTP status code cannot be returned
	// to the client via an HTTP redirect.)
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")

	// Thee authorization server does not support
	// the revocation of the presented token type.
	ErrUnsupportedTokenType = errors.New("unsupported_token_type")

	ErrInvalidRedirectUri = errors.New("invalid_redirect_uri")
)

type errorer interface {
	error() error
}
