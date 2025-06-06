package jwtauth

import (
	"encoding/json"
	"maps"
	"net/http"
	"time"
)

// TokenResponse represents the structure for JWT token and related configuration data
type TokenResponse struct {
	AccessToken      string            `json:"access_token"`      // JWT access token
	RefreshToken     string            `json:"refresh_token"`     // Refresh token for token renewal
	Domain           string            `json:"domain"`            // Cookie domain (optional)
	Path             string            `json:"path"`              // Cookie path (optional)
	ExpiresAt        time.Time         `json:"expires_at"`        // Token expiration time
	HttpOnly         bool              `json:"http_only"`         // HttpOnly flag for cookies
	AdditionalFields map[string]string `json:"additional_fields"` // Additional data to be included in response
}

// SendTokensToWeb sends access and refresh tokens to web clients.
// The refresh token is set in an HTTP cookie, while the access token and any additional fields
// are sent in the JSON response body. This approach is suitable for web applications.
func (m *Manager) SendTokensToWeb(w http.ResponseWriter, resp *TokenResponse, httpStatus int) {
	m.setRefreshTokenCookie(w, resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{AccessTokenKey: resp.AccessToken}

	if len(resp.AdditionalFields) > 0 {
		maps.Copy(responseBody, resp.AdditionalFields)
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// SendTokensToMobileApp sends both access and refresh tokens in the JSON response body.
// This approach is suitable for mobile applications where cookie storage might not be optimal.
// Additional fields can be included in the response if specified in the TokenResponse.
func (m *Manager) SendTokensToMobileApp(w http.ResponseWriter, resp *TokenResponse, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	responseBody := map[string]string{
		AccessTokenKey:  resp.AccessToken,
		RefreshTokenKey: resp.RefreshToken,
	}

	if len(resp.AdditionalFields) > 0 {
		maps.Copy(responseBody, resp.AdditionalFields)
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// SetRefreshTokenCookie sets the refresh token in an HTTP cookie with the provided configuration data.
// The cookie will be set with the specified domain, path, expiration time, and HttpOnly flag.
func (m *Manager) setRefreshTokenCookie(w http.ResponseWriter, resp *TokenResponse) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenKey,
		Value:    resp.RefreshToken,
		Domain:   resp.Domain,
		Path:     resp.Path,
		Expires:  resp.ExpiresAt,
		HttpOnly: resp.HttpOnly,
	})
}
