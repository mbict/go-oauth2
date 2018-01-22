package jwt

import (
	"context"
	"github.com/mbict/go-oauth2"
	"time"
	"github.com/mbict/go-oauth2/token/hmac"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
)

type Strategy struct {
	hmacSha               *hmac.HMACsha
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
	signature := uuid.Must(uuid.NewV4()).String()
	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			ExpiresAt: int64(s.accessTokenLifespan),
			Id:        signature,
			IssuedAt:  0,
			Issuer:    "",
			NotBefore: 0,
			Subject:   session.UserId(),
		},
		Scopes: session.GrantedScopes(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := jwtToken.SignedString(s.hmacSha.GlobalSecret)
	if err != nil {
		return "", "", err
	}

	session.SetExpiresAt(time.Now().Add(s.accessTokenLifespan))
	return 	signature, token, err
}

func (s *Strategy) ValidateAccessToken(_ context.Context, session oauth2.Session, token string) error {
	/*
	jwtToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.hmacSha.GlobalSecret, nil
	})

	if err != nil {
		if e, ok := err.(*jwt.ValidationError); ok {
			switch {
			case e.Errors&jwt.ValidationErrorMalformed != 0:
				// Token is malformed
				return nil, ErrTokenMalformed
			case e.Errors&jwt.ValidationErrorExpired != 0:
				// Token is expired
				return nil, ErrTokenExpired
			case e.Errors&jwt.ValidationErrorNotValidYet != 0:
				// Token is not active yet
				return nil, ErrTokenNotActive
			case e.Inner != nil:
				// report e.Inner
				return nil, e.Inner
			}
			// We have a ValidationError but have no specific Go kit error for it.
			// Fall through to return original error.
		}
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, ErrTokenInvalid
	}

	if time.Now().After(session.ExpiresAt()) {
		return oauth2.ErrSessionExpired
	}
	return nil
	*/
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
	hmacsha := &hmac.HMACsha{
		AuthCodeEntropy: codeEntropy,
		GlobalSecret:    secret,
	}

	return &Strategy{
		hmacSha:               hmacsha,
		authorizeCodeLifespan: authorizeCodeLifespan,
		accessTokenLifespan:   accessTokenLifespan,
	}

}
