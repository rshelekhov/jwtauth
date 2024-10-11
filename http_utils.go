package jwtauth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
)

// GetTokenFromHeader retrieves the JWT token from the "Authorization" HTTP header.
// It expects the token to be in the format "Bearer <token>".
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
func GetTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(AccessTokenKey)
	if err != nil {
		return ""
	}

	return cookie.Value
}

// GetRefreshTokenFromCookie retrieves the refresh token from a cookie named "refresh_token".
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
	return r.URL.Query().Get(AccessTokenKey)
}

func SetTokenCookie(w http.ResponseWriter, name, value, domain, path string, expiresAt time.Time, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expiresAt,
		HttpOnly: httpOnly,
	})
}

func SetRefreshTokenCookie(w http.ResponseWriter, refreshToken, domain, path string, expiresAt time.Time, httpOnly bool) {
	SetTokenCookie(w, RefreshTokenKey, refreshToken, domain, path, expiresAt, httpOnly)
}

func SendTokensToWeb(w http.ResponseWriter, data *ssov1.TokenData, httpStatus int) {
	SetRefreshTokenCookie(w,
		data.GetRefreshToken(),
		data.GetDomain(),
		data.GetPath(),
		data.GetExpiresAt().AsTime(),
		data.GetHttpOnly(),
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{AccessTokenKey: data.AccessToken}

	if len(data.AdditionalFields) > 0 {
		for key, value := range data.AdditionalFields {
			responseBody[key] = value
		}
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		return
	}
}

func SendTokensToMobileApp(w http.ResponseWriter, data *ssov1.TokenData, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{AccessTokenKey: data.AccessToken, RefreshTokenKey: data.RefreshToken}

	if len(data.AdditionalFields) > 0 {
		for key, value := range data.AdditionalFields {
			responseBody[key] = value
		}
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		return
	}
}
