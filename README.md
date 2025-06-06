# Go JWT Authentication Library with JWKS Support

A lightweight, secure JWT authentication library for Go applications with JSON Web Key Set (JWKS) support. Features automatic key rotation, middleware for HTTP servers, and flexible token storage options.

## Features

- JWKS (JSON Web Key Set) support with automatic key rotation
- In-memory cache for JWKS to minimize HTTP requests
- Thread-safe JWKS operations
- Configurable request timeout for JWKS fetching
- Functional options pattern for flexible configuration
- Multiple token extraction strategies:
  - From gRPC metadata
  - From HTTP headers (Authorization Bearer token)
  - From HTTP cookies
- Middleware support for both gRPC and HTTP servers
- Context-based token management
- Flexible token handling for web and mobile applications
- Configurable token expiration
- Easy integration with existing applications
- Support for both local and remote JWKS providers

## Installation

```bash
go get github.com/rshelekhov/jwtauth
```

## Usage

### 1. Initializing the JWT Manager in the auth service

```go
package main

import (
    "net/http"

    "github.com/rshelekhov/jwtauth"
    "github.com/your-org/your-project/auth"
    "github.com/your-org/your-project/adapter"
)

func main() {
    // Initialize your auth usecase
    authUsecase := auth.NewUsecase(...)

    // Create JWKS adapter for local access
    jwksAdapter := adapter.NewJWKSAdapter(authUsecase)

    // Initialize local JWKS provider
    jwksProvider := jwtauth.NewLocalJWKSProvider(jwksAdapter)

    // Initialize JWT manager without appID
    jwtManager, err := jwtauth.NewManager(jwksProvider)
    if err != nil {
        log.Fatalf("failed to initialize JWT manager: %v", err)
    }
}
```

### 2. Initializing the JWT Manager in the other services

```go
package main

import (
    "net/http"
    "time"

    "github.com/rshelekhov/jwtauth"
)

func main() {
    // Initialize remote JWKS provider
    remoteProvider := jwtauth.NewRemoteJWKSProvider("https://your-auth-server/.well-known/jwks.json")

    // Initialize JWT manager with options
    jwtManager, err := jwtauth.NewManager(
        remoteProvider,
        jwtauth.WithAppID("your-app-id"),
        jwtauth.WithTimeout(10 * time.Second), // Custom timeout for JWKS requests
    )
    if err != nil {
        log.Fatalf("failed to initialize JWT manager: %v", err)
    }
}
```

### Configuration Options

The library uses the functional options pattern for flexible configuration:

```go
// Set the application ID for token verification
jwtManager, err := jwtauth.NewManager(provider, jwtauth.WithAppID("your-app-id"))

// Set a custom timeout for JWKS requests (default is 5 seconds)
jwtManager, err := jwtauth.NewManager(provider, jwtauth.WithTimeout(10 * time.Second))

// Combine multiple options
jwtManager, err := jwtauth.NewManager(
    provider,
    jwtauth.WithAppID("your-app-id"),
    jwtauth.WithTimeout(3 * time.Second),
)
```

### Middleware for Different Protocols

#### gRPC Middleware

```go
// Use as a gRPC unary server interceptor
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(jwtManager.UnaryServerInterceptor()),
)
```

#### HTTP Middleware

```go
// Wrap your HTTP handler with JWT verification
protectedHandler := jwtManager.HTTPMiddleware(yourHandler)
```

### Web Application Integration

```go
func (h *handler) handleLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to web client
    tokenResp := &jwtauth.TokenResponse{
        AccessToken:  "generated-access-token",
        RefreshToken: "generated-refresh-token",
        Domain:      "yourdomain.com",
        Path:        "/",
        ExpiresAt:   time.Now().Add(24 * time.Hour),
        HttpOnly:    true,
    }

    h.jwtManager.SendTokensToWeb(w, tokenResp, http.StatusOK)
}
```

### Mobile Application Integration

```go
func (h *handler) handleMobileLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to mobile client
    tokenResp := &jwtauth.TokenResponse{
        AccessToken:  "generated-access-token",
        RefreshToken: "generated-refresh-token",
        AdditionalFields: map[string]string{
            "user_id": "123",
            "role": "user",
        },
    }

    h.jwtManager.SendTokensToMobileApp(w, tokenResp, http.StatusOK)
}
```

### Token Response Structure

The library provides a flexible TokenResponse structure that can be used to handle various authentication scenarios:

```go
type TokenResponse struct {
    AccessToken      string            // JWT access token
    RefreshToken     string            // Refresh token for token renewal
    Domain           string            // Cookie domain (optional)
    Path             string            // Cookie path (optional)
    ExpiresAt        time.Time         // Token expiration time
    HttpOnly         bool              // HttpOnly flag for cookies
    AdditionalFields map[string]string // Additional data to be included in response
}
```

### Token Verification and User Extraction

```go
// Extract user ID from token
userID, err := jwtManager.ExtractUserID(ctx, appID)

// Verify token manually
err := jwtManager.verifyToken(ctx, appID, tokenString)
```

## Error Handling

The library provides predefined errors for common scenarios:

```go
switch err {
case jwtauth.ErrNoTokenFound:
    // Handle missing token
case jwtauth.ErrInvalidToken:
    // Handle invalid token
case jwt.ErrTokenExpired:
    // Handle expired token
default:
    // Handle general authorization failure
}
```

## Security Considerations

- Always use HTTPS for token transmission
- Set appropriate token expiration times
- Use HttpOnly cookies for web applications
- Keep your JWKS endpoint secure
- Regularly rotate your signing keys

## License

MIT License - see the LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## Support

For questions and support, please open an issue in the GitHub repository.
