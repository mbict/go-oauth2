package oauth2

type TokenStrategy interface {
	Signature(token string) (string, error)
	Validate(token string) error
	Generate(request Request) (signature string, token string, err error)
}
