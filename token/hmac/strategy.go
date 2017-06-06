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

func (s *Strategy) GenerateAuthorizeCode(_ context.Context, session oauth2.Session) (string, string, error) {
	signature, token, err := s.hmacSha.Generate()
	if err != nil {
		return "", "", err
	}

	session.SetExpiresAt(time.Now().Add(s.authorizeCodeLifespan))
	return signature, token, err
}

func (s *Strategy) ValidateAuthorizeCode(_ context.Context, session oauth2.Session, token string) error {
	if err := s.hmacSha.Validate(token); err != nil {
		return err
	}

	if time.Now().After(session.ExpiresAt()) {
		return oauth2.ErrSessionExpired
	}
	return nil
}

func (s *Strategy) AccessTokenSignature(token string) (string, error) {
	return s.hmacSha.Signature(token)
}

func (s *Strategy) GenerateAccessToken(_ context.Context, session oauth2.Session) (string, string, error) {
	signature, token, err := s.hmacSha.Generate()
	if err != nil {
		return "", "", err
	}

	session.SetExpiresAt(time.Now().Add(s.accessTokenLifespan))
	return signature, token, err
}

func (s *Strategy) ValidateAccessToken(_ context.Context, session oauth2.Session, token string) error {
	if err := s.hmacSha.Validate(token); err != nil {
		return err
	}

	if time.Now().After(session.ExpiresAt()) {
		return oauth2.ErrSessionExpired
	}
	return nil
}

func (s *Strategy) RefreshTokenSignature(token string) (string, error) {
	return s.hmacSha.Signature(token)
}

func (s *Strategy) GenerateRefreshToken(_ context.Context, _ oauth2.Session) (string, string, error) {
	return s.hmacSha.Generate()
}

func (s *Strategy) ValidateRefreshToken(_ context.Context, _ oauth2.Session, token string) error {
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
