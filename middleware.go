package jwtauth

import (
	"net/http"
	"strings"
)

// Verifier http middleware handler verify a JWT string from a http request.
//
// Verifier will search for a JWT token in a http reqiest in order:
// 1. 'Authorization: BEARER T' request header
// 2. Cookie 'access_token' value
// 3. Query 'access_token' value
//
// The Verifier always calls the next http handler in sequence, which can either
// be the generic `jwtauth.Authenticator` middleware or your own custom handler
// which checks the request context jwt token and error to prepare a custom
// http response.
func Verifier(j *TokenService) func(http.Handler) http.Handler {
	return j.Verify(GetTokenFromHeader, GetTokenFromCookie, GetTokenFromQuery)
}

// Authenticator is a middleware function that ensures the request contains a valid token.
// If no token is found, or it is invalid, it returns an Unauthorized response (HTTP 401).
// Otherwise, the request is passed along to the next handler in the chain.
func Authenticator() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			token, err := GetTokenFromContext(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if len(token) == 0 {
				http.Error(w, ErrNoTokenFound.Error(), http.StatusUnauthorized)
				return
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(hfn)
	}
}

// GetTokenFromHeader retrieves the JWT token from the "Authorization" HTTP header.
// It expects the token to be in the format "Bearer <token>".
// If the token is not in the proper format or is missing, it returns an empty string.
func GetTokenFromHeader(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if len(token) > 7 && strings.ToUpper(token[0:6]) == "BEARER" {
		return token[7:]
	}

	return ""
}

// GetRefreshTokenFromHeader retrieves the refresh token from the request header.
// If the refresh token is not found in the header, it attempts to retrieve it from the request body (form data).
func GetRefreshTokenFromHeader(r *http.Request) (string, error) {
	refreshToken := r.Header.Get(RefreshTokenKey)
	if refreshToken == "" {
		// If the refreshToken is not in the headers, we try to extract it from the request body
		err := r.ParseForm()
		if err != nil {
			return "", err
		}

		refreshToken = r.FormValue(refreshToken)
	}

	return refreshToken, nil
}

// GetTokenFromCookie retrieves the JWT token from a cookie named "access_token".
// If the cookie is not present or an error occurs, it returns an empty string.
func GetTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(AccessTokenKey)
	if err != nil {
		return ""
	}

	return cookie.Value
}

// GetRefreshTokenFromCookie retrieves the refresh token from a cookie named "refresh_token".
// If the cookie is not present or an error occurs, it returns an error.
func GetRefreshTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(RefreshTokenKey)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

// GetTokenFromQuery retrieves the JWT token from the query parameters of the HTTP request.
// It expects the query parameter to be named "access_token".
func GetTokenFromQuery(r *http.Request) string {
	// Get token from query param named "jwtoken".
	return r.URL.Query().Get(AccessTokenKey)
}
