package jwtauth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrUnauthorized             = errors.New("unauthorized")
	ErrNoTokenFound             = errors.New("no token found")
	ErrInvalidToken             = errors.New("invalid token")
	ErrUnexpectedSigningMethod  = errors.New("unexpected signing method")
	ErrTokenNotFoundInCtx       = errors.New("token not found in context")
	ErrUserIDNotFoundInCtx      = errors.New("user id not found in context")
	ErrAccessTokenNotFoundInCtx = errors.New("access token not found in context")
	ErrFailedToParseTokenClaims = errors.New("failed to parse token claims from context")
	ErrKidNotFoundInTokenHeader = errors.New("kid not found in token header")
	ErrKidIsNotAString          = errors.New("kid is not a string")
)

func Errors(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return jwt.ErrTokenExpired
	case errors.Is(err, jwt.ErrSignatureInvalid):
		return jwt.ErrSignatureInvalid
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return jwt.ErrTokenNotValidYet
	default:
		return ErrUnauthorized
	}
}
