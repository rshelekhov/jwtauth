package jwtauth

import (
	"encoding/json"
	"fmt"
	"github.com/rshelekhov/jwtauth/cache"
	"log/slog"
	"net/http"
	"time"
)

// JWK represents a JSON Web Key structure containing the necessary fields
// for RSA public key construction
type JWK struct {
	Alg string `json:"alg,omitempty"` // The specific cryptographic algorithm used with the key.
	Kty string `json:"kty,omitempty"` // The family of cryptographic algorithms used with the key.
	Use string `json:"use,omitempty"` // How the key was meant to be used; sig represents the signature
	Kid string `json:"kid,omitempty"` // The unique identifier for the key.

	// For RSA keys
	N string `json:"n,omitempty"` // The modulus for the RSA public key
	E string `json:"e,omitempty"` // The exponent for the RSA public key.
}

// JWKSResponse represents the structure of the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK         `json:"keys"`
	TTL  time.Duration `json:"ttl"`
}

const JWKS = "jwks"

// getJWK retrieves a JWK by its key ID (kid) from the cache or fetches new JWKS if needed
// Returns the matching JWK or an error if not found
func (m *manager) getJWK(appID, kid string) (*JWK, error) {
	const op = "jwt.manager.getJWK"

	slog.Info("Starting getJWK",
		"op", op,
		"appID", appID,
		"kid", kid)

	// Construct cache key using appID
	cacheKey := createCacheKey(appID)
	slog.Info("Created cache key", "cacheKey", cacheKey)

	jwks, found := m.getCachedJWKS(cacheKey)
	slog.Info("Attempted to get JWKS from cache",
		"found", found,
		"jwksLength", len(jwks))

	if !found {
		slog.Info("JWKS not found in cache, updating")
		if err := m.updateJWKS(appID); err != nil {
			slog.Error("Failed to update JWKS",
				"error", err)
			return nil, fmt.Errorf("%s: failed to update JWKS: %w", op, err)
		}
	}

	// If not in cache or cache miss, fetch new JWKS from URL
	if len(jwks) == 0 {
		slog.Info("Empty JWKS, fetching new ones")
		if err := m.updateJWKS(appID); err != nil {
			slog.Error("Failed to update JWKS after empty result",
				"error", err)
			return nil, fmt.Errorf("%s: failed to update JWKS: %w", op, err)
		}

		jwks, found = m.getCachedJWKS(cacheKey)
		if !found {
			slog.Error("JWKS not found after update")
			return nil, fmt.Errorf("%s: JWKS not found after update", op)
		}
	}

	// Find the JWK with the matching key ID
	slog.Info("Searching for matching JWK",
		"kid", kid,
		"availableJWKs", len(jwks))
	for _, jwk := range jwks {
		if jwk.Kid == kid {
			slog.Info("Found matching JWK")
			return &jwk, nil
		}
	}

	slog.Error("JWK not found",
		"kid", kid,
		"availableKids", func() []string {
			kids := make([]string, len(jwks))
			for i, jwk := range jwks {
				kids[i] = jwk.Kid
			}
			return kids
		}())

	return nil, fmt.Errorf("%s: JWK with kid %s not found", op, kid)
}

// updateJWKS fetches fresh JWKS from the configured URL and updates the cache
// Returns an error if the fetch or update fails
func (m *manager) updateJWKS(appID string) error {
	const op = "jwt.manager.updateJWKS"

	slog.Info("Starting JWKS update",
		"op", op,
		"appID", appID)

	if m.jwksURL == "" {
		slog.Error("JWKS URL not configured")
		return fmt.Errorf("%s: jwksURL is not configured for JWT Manager", op)
	}

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, m.jwksURL, nil)
	if err != nil {
		slog.Error("Failed to create HTTP request",
			"error", err,
			"url", m.jwksURL)
		return fmt.Errorf("%s: failed to create HTTP request: %w", op, err)
	}

	req.Header.Add(AppIDHeader, appID)
	slog.Info("Making JWKS request",
		"url", m.jwksURL,
		"appID", appID)

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Failed to fetch JWKS",
			"error", err)
		return fmt.Errorf("%s: failed to fetch JWKS: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Bad status code from JWKS endpoint",
			"statusCode", resp.StatusCode)
		return fmt.Errorf("%s: failed to fetch JWKS: status code %d", op, resp.StatusCode)
	}

	var jwks JWKSResponse
	if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		slog.Error("Failed to decode JWKS response",
			"error", err)
		return fmt.Errorf("%s: failed to decode JWKS response: %w", op, err)
	}

	slog.Info("Successfully decoded JWKS response",
		"keysCount", len(jwks.Keys))

	// Construct cache key using appID
	cacheKey := createCacheKey(appID)

	ttl := cache.DefaultExpiration
	if jwks.TTL > 0 {
		ttl = jwks.TTL
	}

	slog.Info("Setting JWKS in cache",
		"cacheKey", cacheKey,
		"ttl", ttl)

	m.mu.RLock()
	m.jwksCache.Set(cacheKey, jwks.Keys, ttl)
	m.mu.RUnlock()

	return nil
}

// getCachedJWKS returns a cached JWKS from the cache or nil if not found
func (m *manager) getCachedJWKS(cacheKey string) ([]JWK, bool) {
	slog.Info("Getting JWKS from cache",
		"cacheKey", cacheKey)

	m.mu.RLock()
	defer m.mu.RUnlock()

	if value, found := m.jwksCache.Get(cacheKey); found {
		if jwks, ok := value.([]JWK); ok {
			slog.Info("Found JWKS in cache",
				"keysCount", len(jwks))
			return jwks, true
		}
		slog.Error("Cache value type assertion failed")
	}

	slog.Info("JWKS not found in cache")

	return nil, false
}

// createCacheKey creates a cache key based on the appID
func createCacheKey(appID string) string {
	return fmt.Sprintf("%s:%s", JWKS, appID)
}
