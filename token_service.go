package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rshelekhov/jwtauth/lib/cache"
	ssogrpc "github.com/rshelekhov/sso-grpc-client"

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

const (
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
			AppId: j.AppID,
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
