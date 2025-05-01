package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type (
	JWKSProvider interface {
		GetJWKS(ctx context.Context, appID string) (JWKSResponse, error)
	}

	JWKSService interface {
		GetJWKS(ctx context.Context, appID string) (JWKSResponse, error)
	}
)

type LocalJWKSProvider struct {
	JWKSService JWKSService
}

func NewLocalJWKSProvider(jwksService JWKSService) *LocalJWKSProvider {
	return &LocalJWKSProvider{
		JWKSService: jwksService,
	}
}

// GetJWKS fetches the JWKS from the local service
// Returns the JWKS or an error if the fetch fails
func (p *LocalJWKSProvider) GetJWKS(ctx context.Context, appID string) (JWKSResponse, error) {
	const op = "jwtauth.LocalJWKSProvider.GetJWKS"

	jwks, err := p.JWKSService.GetJWKS(ctx, appID)
	if err != nil {
		return JWKSResponse{}, fmt.Errorf("%s: failed to get JWKS: %w", op, err)
	}

	return jwks, nil
}

type RemoteJWKSProvider struct {
	jwksURL string
}

func NewRemoteJWKSProvider(jwksURL string) *RemoteJWKSProvider {
	return &RemoteJWKSProvider{
		jwksURL: jwksURL,
	}
}

// GetJWKS fetches the JWKS from the remote URL
// Returns the JWKS or an error if the fetch or decode fails
func (p *RemoteJWKSProvider) GetJWKS(ctx context.Context, appID string) (JWKSResponse, error) {
	const op = "jwtauth.RemoteJWKSProvider.GetJWKS"

	if p.jwksURL == "" {
		return JWKSResponse{}, fmt.Errorf("%s: jwksURL is not configured for JWKS Provider", op)
	}

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return JWKSResponse{}, fmt.Errorf("%s: failed to create HTTP request: %w", op, err)
	}

	req.Header.Add(AppIDHeader, appID)

	resp, err := client.Do(req)
	if err != nil {
		return JWKSResponse{}, fmt.Errorf("%s: failed to fetch JWKS: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JWKSResponse{}, fmt.Errorf("%s: failed to fetch JWKS: status code %d", op, resp.StatusCode)
	}

	var jwks JWKSResponse
	if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return JWKSResponse{}, fmt.Errorf("%s: failed to decode JWKS response: %w", op, err)
	}

	return jwks, nil
}
