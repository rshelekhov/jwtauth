package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rshelekhov/jwtauth/lib/cache"
	ssogrpc "github.com/rshelekhov/sso-grpc-client"
	"google.golang.org/grpc/metadata"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
)

type TokenService struct {
	ssoClient *ssogrpc.Client
	jwksCache *cache.Cache
	mu        sync.RWMutex
	AppID     string
}

func New(ssoClient *ssogrpc.Client, appID string) *TokenService {
	return &TokenService{
		ssoClient: ssoClient,
		jwksCache: cache.New(),
		AppID:     appID,
	}
}

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

const (
	AccessTokenKey  = "access_token"
	RefreshTokenKey = "refresh_token"
	UserID          = "user_id"
	JWKS            = "jwks"
	Kid             = "kid"
)

type contextKey string

const (
	AccessTokenCtxKey contextKey = "access_token"
)

// Verify verifies the presence of a JWT token using multiple strategies (header, cookie, query).
// It validates the token and passes it to the next handler if successful, otherwise returns
// an Unauthorized response.
func (j *TokenService) Verify(findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			ctx := r.Context()
			ctx = context.WithValue(ctx, AccessTokenCtxKey, accessToken)

			// Proceed with the request using the modified context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FindToken searches for a JWT token using the provided search functions (e.g., header, cookie, query).
// It returns the token if found and valid, otherwise it returns an error.
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
// It returns an error if the refresh token cannot be found or an error occurs during retrieval.
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
	jwks, err := j.GetJWKS(ctx)
	if err != nil {
		return nil, err
	}

	// Parse the tokenData using the public key
	tokenParsed, err := jwt.Parse(accessTokenString, func(token *jwt.Token) (interface{}, error) {
		kidRaw, ok := token.Header[Kid]
		if !ok {
			return nil, ErrKidNotFoundInTokenHeader
		}

		kid, ok := kidRaw.(string)
		if !ok {
			return nil, ErrKidIsNotAString
		}

		jwk, err := getJWKByKid(jwks, kid)
		if err != nil {
			return nil, err
		}

		n, err := base64.RawURLEncoding.DecodeString(jwk.GetN())
		if err != nil {
			return nil, err
		}

		e, err := base64.RawURLEncoding.DecodeString(jwk.GetE())
		if err != nil {
			return nil, err
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	return tokenParsed, nil
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) used for token verification from the cache or the SSO server.
// If the JWKS is not in the cache, it fetches it from the SSO server and stores it with a TTL.
func (j *TokenService) GetJWKS(ctx context.Context) ([]*ssov1.JWK, error) {
	var jwks []*ssov1.JWK

	j.mu.RLock()
	cacheValue, found := j.jwksCache.Get(JWKS)
	j.mu.RUnlock()

	if found {
		cachedJWKS, ok := cacheValue.([]*ssov1.JWK)
		if !ok {
			return nil, errors.New("invalid JWKS cache value type")
		}

		jwks = make([]*ssov1.JWK, len(cachedJWKS))
		copy(jwks, cachedJWKS)
	} else {
		jwksResponse, err := j.ssoClient.Api.GetJWKS(ctx, &ssov1.GetJWKSRequest{
			AppID: j.AppID,
		})
		if err != nil {
			return nil, err
		}

		jwks = jwksResponse.GetJwks()
		ttl := time.Duration(jwksResponse.GetTtl().Seconds) * time.Second

		j.mu.Lock()
		j.jwksCache.Set(JWKS, jwks, ttl)
		j.mu.Unlock()
	}

	return jwks, nil
}

func getJWKByKid(jwks []*ssov1.JWK, kid string) (*ssov1.JWK, error) {
	for _, jwk := range jwks {
		if jwk.GetKid() == kid {
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("JWK with kid %s not found", kid)
}

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

func GetTokenFromContext(ctx context.Context) (string, error) {
	token, ok := ctx.Value(AccessTokenCtxKey).(string)
	if !ok {
		return "", ErrTokenNotFoundInCtx
	}

	return token, nil
}

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

func AddAccessTokenToMetadata(ctx context.Context) (context.Context, error) {
	accessToken, ok := ctx.Value(AccessTokenCtxKey).(string)
	if !ok {
		return nil, ErrAccessTokenNotFoundInCtx
	}

	md := metadata.Pairs(AccessTokenKey, accessToken)

	newCtx := metadata.NewOutgoingContext(ctx, md)

	return newCtx, nil
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
