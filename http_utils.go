package jwtauth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// TokenData represents the structure for JWT token and related configuration data
type TokenData struct {
	AccessToken      string            `json:"access_token"`      // JWT access token
	RefreshToken     string            `json:"refresh_token"`     // Refresh token for token renewal
	Domain           string            `json:"domain"`            // Cookie domain (optional)
	Path             string            `json:"path"`              // Cookie path (optional)
	ExpiresAt        time.Time         `json:"expires_at"`        // Token expiration time
	HttpOnly         bool              `json:"http_only"`         // HttpOnly flag for cookies
	AdditionalFields map[string]string `json:"additional_fields"` // Additional data to be included in response
}

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

// SetRefreshTokenCookie sets the refresh token in an HTTP cookie with the provided configuration data.
// The cookie will be set with the specified domain, path, expiration time, and HttpOnly flag.
func SetRefreshTokenCookie(w http.ResponseWriter, data *TokenData) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenKey,
		Value:    data.RefreshToken,
		Domain:   data.Domain,
		Path:     data.Path,
		Expires:  data.ExpiresAt,
		HttpOnly: data.HttpOnly,
	})
}

// SendTokensToWeb sends access and refresh tokens to web clients.
// The refresh token is set in an HTTP cookie, while the access token and any additional fields
// are sent in the JSON response body. This approach is suitable for web applications.
func SendTokensToWeb(w http.ResponseWriter, data *TokenData, httpStatus int) {
	SetRefreshTokenCookie(w, data)
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

// SendTokensToMobileApp sends both access and refresh tokens in the JSON response body.
// This approach is suitable for mobile applications where cookie storage might not be optimal.
// Additional fields can be included in the response if specified in the TokenData.
func SendTokensToMobileApp(w http.ResponseWriter, data *TokenData, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{
		AccessTokenKey:  data.AccessToken,
		RefreshTokenKey: data.RefreshToken,
	}

	if len(data.AdditionalFields) > 0 {
		for key, value := range data.AdditionalFields {
			responseBody[key] = value
		}
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		return
	}
}
