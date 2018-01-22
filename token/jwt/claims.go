package jwt

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	jwt.StandardClaims

	Scopes []string `json:"scopes,omitempty"`
}
