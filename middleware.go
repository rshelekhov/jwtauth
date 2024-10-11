package jwtauth

import (
	"net/http"
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
