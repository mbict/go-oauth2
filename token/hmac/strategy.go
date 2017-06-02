package hmac

import (
	"context"
	"github.com/mbict/go-oauth2"
	"time"
)

type Strategy struct {
	hmacSha               *HMACsha
	authorizeCodeLifespan time.Duration
	accessTokenLifespan   time.Duration
}

func (s *Strategy) AuthorizeCodeLifespan() time.Duration {
	return s.authorizeCodeLifespan
}

func (s *Strategy) AccessTokenLifespan() time.Duration {
	return s.accessTokenLifespan
}

func (s *Strategy) AuthorizeCodeSignature(token string) (string, error) {
	return s.hmacSha.Signature(token)
}

func (s *Strategy) GenerateAuthorizeCode(ctx context.Context, request oauth2.Request) (string, string, error) {
	signature, token, err := s.hmacSha.Generate()
	if err != nil {
		return "", "", err
	}

	request.Session().SetExpiresAt(time.Now().Add(s.authorizeCodeLifespan))
	return signature, token, err
}

func (s *Strategy) ValidateAuthorizeCode(ctx context.Context, request oauth2.Request, token string) error {
	if err := s.hmacSha.Validate(token); err != nil {
		return err
	}

	if time.Now().After(request.Session().ExpiresAt()) {
		return oauth2.ErrSessionExpired
	}
	return nil
}

func (s *Strategy) AccessTokenSignature(token string) (string, error) {
	return s.hmacSha.Signature(token)
}

func (s *Strategy) GenerateAccessToken(ctx context.Context, request oauth2.Request) (string, string, error) {
	signature, token, err := s.hmacSha.Generate()
	if err != nil {
		return "", "", err
	}

	request.Session().SetExpiresAt(time.Now().Add(s.accessTokenLifespan))
	return signature, token, err
}

func (s *Strategy) ValidateAccessToken(ctx context.Context, request oauth2.Request, token string) error {
	if err := s.hmacSha.Validate(token); err != nil {
		return err
	}

	if time.Now().After(request.Session().ExpiresAt()) {
		return oauth2.ErrSessionExpired
	}
	return nil
}

func (s *Strategy) RefreshTokenSignature(token string) (string, error) {
	return s.hmacSha.Signature(token)
}

func (s *Strategy) GenerateRefreshToken(ctx context.Context, request oauth2.Request) (string, string, error) {
	return s.hmacSha.Generate()
}

func (s *Strategy) ValidateRefreshToken(ctx context.Context, request oauth2.Request, token string) error {
	return s.hmacSha.Validate(token)
}

func NewStrategy(codeEntropy int, secret []byte, authorizeCodeLifespan time.Duration, accessTokenLifespan time.Duration) oauth2.TokenStrategy {
	hmacsha := &HMACsha{
		AuthCodeEntropy: codeEntropy,
		GlobalSecret:    secret,
	}
	return &Strategy{
		hmacSha:               hmacsha,
		authorizeCodeLifespan: authorizeCodeLifespan,
		accessTokenLifespan:   accessTokenLifespan,
	}

}
