package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"sync"

	"github.com/rshelekhov/jwtauth/lib/cache"
)

// TokenService handles JWT token operations including verification and parsing
// using JSON Web Key Sets (JWKS) for signature validation
type TokenService struct {
	// Application ID for verification tokens
	// Use in the middleware to verify tokens
	appID string

	// URL to fetch JWKS from auth service (optional)
	jwksEndpoint string

	// Cache to store JWKS
	jwksCache *cache.Cache

	// Mutex for thread-safe cache operations
	mu sync.RWMutex
}

// JWK represents a JSON Web Key structure containing the necessary fields
// for RSA public key construction
type JWK struct {
	Alg string `json:"alg"` // Algorithm used for the key
	Kty string `json:"kty"` // Key type (e.g., "RSA")
	Use string `json:"use"` // Key usage (e.g., "sig" for signature)
	Kid string `json:"kid"` // Key identifier
	N   string `json:"n"`   // RSA public key modulus
	E   string `json:"e"`   // RSA public key exponent
}

// JWKSResponse represents the structure of the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// New creates a new instance of TokenService with the specified options.
// If no options are provided, the default values are used.
// JWKS URL is empty by default.
func New(opts ...TokenServiceOption) *TokenService {
	ts := &TokenService{
		jwksCache: cache.New(),
	}

	for _, opt := range opts {
		opt(ts)
	}

	return ts
}

type TokenServiceOption func(service *TokenService)

// WithJWKSEndpoint specifies the URL to fetch JWKS from auth service
func WithJWKSEndpoint(url string) TokenServiceOption {
	return func(s *TokenService) {
		s.jwksEndpoint = url
	}
}

// WithAppID specifies the application ID for verification tokens middleware
func WithAppID(appID string) TokenServiceOption {
	return func(s *TokenService) {
		s.appID = appID
	}
}

// Common constants used throughout the package
const (
	AppIDHeader     = "X-App-ID"
	AppIDCtxKey     = "app_id"
	AccessTokenKey  = "access_token"
	RefreshTokenKey = "refresh_token"
	UserID          = "user_id"
	JWKS            = "jwks"
	Kid             = "kid"
)

// Verify verifies the presence of a JWT token using multiple strategies (header, cookie, query).
// It validates the token and passes it to the next handler if successful, otherwise returns
// an Unauthorized response.
func (j *TokenService) Verify(findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()

			if j.appID == "" {
				// We verify tokens in the SSO Gateway, so we need to get the appID from the header request
				var appIDFromRequest string

				if appIDFromRequest = r.Header.Get(AppIDHeader); appIDFromRequest == "" {
					http.Error(w, ErrNoAppIDFoundInHeaderRequest.Error(), http.StatusUnauthorized)
				}

				ctx = context.WithValue(ctx, AppIDCtxKey, appIDFromRequest)
			}

			accessToken, err := j.FindToken(r, findTokenFns...)
			if err != nil {
				if errors.Is(err, ErrNoTokenFound) {
					http.Error(w, ErrNoTokenFound.Error(), http.StatusUnauthorized)
					return
				}

				http.Error(w, err.Error(), http.StatusUnauthorized)

				return
			}

			// Store the access token in the request context
			ctx = context.WithValue(r.Context(), AccessTokenCtxKey, accessToken)

			// Proceed with the request using the modified context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FindToken searches for a JWT token using the provided search functions (e.g., header, cookie, query).
// Returns the found token string or an error if no valid token is found.
func (j *TokenService) FindToken(r *http.Request, findTokenFns ...func(r *http.Request) string) (string, error) {
	var accessTokenString string

	for _, fn := range findTokenFns {
		accessTokenString = fn(r)
		if accessTokenString != "" {
			break
		}
	}

	if accessTokenString == "" {
		return "", ErrNoTokenFound
	}

	if err := j.VerifyToken(r.Context(), accessTokenString); err != nil {
		return "", err
	}

	return accessTokenString, nil
}

// FindRefreshToken attempts to retrieve the refresh token from the request (header or cookie).
// Returns the refresh token string or an error if not found in either location.
func FindRefreshToken(r *http.Request) (string, error) {
	refreshToken, err := GetRefreshTokenFromHeader(r)
	if err != nil {
		return "", err
	}

	if refreshToken == "" {
		refreshToken, err = GetRefreshTokenFromCookie(r)
		if err != nil {
			return "", err
		}
	}

	return refreshToken, nil
}

// VerifyToken checks the validity of the provided access token.
// It parses the token, verifies the signature, and ensures it is not expired.
func (j *TokenService) VerifyToken(ctx context.Context, accessTokenString string) error {
	token, err := j.ParseToken(ctx, accessTokenString)
	if err != nil {
		return Errors(err)
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	return nil
}

// ParseToken parses the given access token string and validates it using the public keys (JWKS).
// It checks the "kid" (key ID) in the token header to select the appropriate public key.
func (j *TokenService) ParseToken(ctx context.Context, accessTokenString string) (*jwt.Token, error) {
	return jwt.Parse(accessTokenString, func(token *jwt.Token) (interface{}, error) {
		kidRaw, ok := token.Header[Kid]
		if !ok {
			return nil, ErrKidNotFoundInTokenHeader
		}

		kid, ok := kidRaw.(string)
		if !ok {
			return nil, ErrKidIsNotAString
		}

		jwk, err := j.getJWK(ctx, kid)
		if err != nil {
			return nil, err
		}

		// Decode the base64 URL-encoded components of the RSA public key
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, err
		}

		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, err
		}

		// Construct the RSA public key from the decoded components
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		// Verify that the token uses RSA signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}

		return pubKey, nil
	})
}

// getJWK retrieves a JWK by its key ID (kid) from the cache or fetches new JWKS if needed
// Returns the matching JWK or an error if not found
func (j *TokenService) getJWK(ctx context.Context, kid string) (*JWK, error) {
	const op = "jwtauth.TokenService.getJWK"

	// Define which appID to use to get JWKS
	appID, err := j.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Construct cache key using appID
	cacheKey := fmt.Sprintf("%s:%s", JWKS, appID)

	// Try to get JWKS from cache first
	j.mu.RLock()
	cacheValue, found := j.jwksCache.Get(cacheKey)
	j.mu.RUnlock()

	var jwks []JWK
	if found {
		if cachedJWKS, ok := cacheValue.([]JWK); ok {
			jwks = cachedJWKS
		}
	}

	// If not in cache or cache miss, fetch new JWKS from URL
	if len(jwks) == 0 {
		if err := j.updateJWKS(ctx, appID); err != nil {
			return nil, fmt.Errorf("%s: failed to update JWKS: %w", op, err)
		}

		j.mu.RLock()
		cachedValue, found := j.jwksCache.Get(cacheKey)
		j.mu.RUnlock()

		if !found {
			return nil, fmt.Errorf("%s: JWKS not found after update", op)
		}

		var ok bool
		jwks, ok = cachedValue.([]JWK)
		if !ok {
			return nil, fmt.Errorf("%s: invalid cache value type", op)
		}
	}

	// Find the JWK with the matching key ID
	for _, jwk := range jwks {
		if jwk.Kid == kid {
			return &jwk, nil
		}
	}

	return nil, fmt.Errorf("%s: JWK with kid %s not found", op, kid)
}

// getAppID returns the appID from the TokenService struct or context.
// If the appID is not found returns an error
func (j *TokenService) getAppID(ctx context.Context) (string, error) {
	if appID := j.appID; appID != "" {
		return appID, nil
	}

	// We try to get appID from context in case we are in the SSO Gateway
	if appIDFromCtx, ok := ctx.Value(AppIDCtxKey).(string); ok {
		return appIDFromCtx, nil
	}
	return "", ErrAppIDNotFoundInCtx
}

// updateJWKS fetches fresh JWKS from the configured URL and updates the cache
// Returns an error if the fetch or update fails
func (j *TokenService) updateJWKS(ctx context.Context, appID string) error {
	const op = "jwtauth.TokenService.updateJWKS"

	if j.jwksEndpoint == "" {
		return fmt.Errorf("%s: JWKS endpoint not configured for TokenService", op)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.jwksEndpoint, nil)
	if err != nil {
		return fmt.Errorf("%s: failed to create request: %w", op, err)
	}

	if appID == "" {
		return fmt.Errorf("%s: appID is empty", op)
	}

	req.Header.Set(AppIDHeader, appID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: failed to fetch JWKS: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: failed to fetch JWKS: status code %d", op, resp.StatusCode)
	}

	var jwksResponse JWKSResponse
	if err = json.NewDecoder(resp.Body).Decode(&jwksResponse); err != nil {
		return fmt.Errorf("%s: failed to decode JWKS response: %w", op, err)
	}

	// Construct cache key using appID
	cacheKey := fmt.Sprintf("%s:%s", JWKS, appID)

	j.mu.RLock()
	j.jwksCache.Set(cacheKey, jwksResponse.Keys, cache.DefaultExpiration)
	j.mu.RUnlock()

	return nil
}

// GetClaimsFromToken extracts the claims from the token in the current context
// Returns the claims as a map or an error if the token is invalid or missing
func (j *TokenService) GetClaimsFromToken(ctx context.Context) (map[string]interface{}, error) {
	accessToken, err := GetTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	token, err := j.ParseToken(ctx, accessToken)
	if err != nil {
		return nil, Errors(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrFailedToParseTokenClaims
	}

	return claims, nil
}

// GetUserID extracts the user ID from the token claims in the current context
// Returns the user ID as a string or an error if not found
func (j *TokenService) GetUserID(ctx context.Context) (string, error) {
	claims, err := j.GetClaimsFromToken(ctx)
	if err != nil {
		return "", err
	}

	userID, ok := claims[UserID]
	if !ok {
		return "", ErrUserIDNotFoundInCtx
	}

	return userID.(string), nil
}
