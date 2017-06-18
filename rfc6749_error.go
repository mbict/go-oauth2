package oauth2

import (
	"github.com/pkg/errors"
	"net/http"
)

const (
	errUnkownError = "unkown_error"
)

type RFC6749Error struct {
	Name        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Uri         string `json:"error_uri,omitempty"`
	Hint        string `json:"hint,omitempty"`
	Debug       string `json:"debug"`
	Code        int    `json:"statusCode,omitempty"`
}

func errorToRFC6749Error(err error) *RFC6749Error {

	if e, ok := err.(*RFC6749Error); ok {
		return e
	}

	switch errors.Cause(err) {

	case ErrAccessDenied:
		return &RFC6749Error{
			Name:        "access_denied",
			Description: "The resource owner or the authorization server denied your request",
			Debug:       err.Error(),
			Code:        http.StatusUnauthorized,
		}

	case ErrUnauthorizedClient:
		return &RFC6749Error{
			Name:        "unauthorized_client",
			Description: "The client is not authorized to request this service",
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}

	case ErrUnsupportedResponseType:
		return &RFC6749Error{
			Name:        "unsupported_response_type",
			Description: "Unsupported response type",
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}

	case ErrInvalidScope:
		return &RFC6749Error{
			Name:        "invalid_scope",
			Description: "The requested scope is invalid, unknown, or malformed",
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}

	case ErrInvalidRedirectUri:
		return &RFC6749Error{
			Name:        "invalid_request",
			Description: "The redirect uri is invalid",
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}

	case ErrInvalidRequest:
		return &RFC6749Error{
			Name:        "invalid_request",
			Description: "Your request is missing required parameters or is malformed",
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}

	default:
		return &RFC6749Error{
			Name:        "server_error",
			Description: "The error is unexpected",
			Debug:       err.Error(),
			Code:        http.StatusInternalServerError,
		}
	}
}

func (e *RFC6749Error) Status() string {
	return http.StatusText(e.Code)
}

func (e *RFC6749Error) Error() string {
	return e.Name
}

func (e *RFC6749Error) Reason() string {
	return e.Hint
}

func (e *RFC6749Error) StatusCode() int {
	return e.Code
}
