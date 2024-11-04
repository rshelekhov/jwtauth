# Go JWT Authentication Library with JWKS Support

A lightweight, secure JWT authentication library for Go applications with JSON Web Key Set (JWKS) support. Features automatic key rotation, middleware for HTTP servers, and flexible token storage options.

## Features

- JWKS (JSON Web Key Set) support with automatic key rotation
- In-memory cache for JWKS to minimize HTTP requests
- Thread-safe operations
- Multiple token extraction strategies (headers, cookies, query parameters)
- Middleware for HTTP servers
- Support for both web and mobile applications
- Refresh token handling
- gRPC metadata support
- Configurable token expiration
- Easy integration with existing applications
- No external authentication service dependencies

## Installation

``` bash
go get github.com/rshelekhov/jwtauth
```

## Usage

### Basic Setup

``` go
package main

import (
    "github.com/rshelekhov/jwtauth"
    "net/http"
)

func main() {
    // Initialize the token service with your JWKS URL
    tokenService := jwtauth.New("https://your-auth-server/.well-known/jwks.json")

    // Use the built-in middleware
    http.Handle("/protected", 
        jwtauth.Verifier(tokenService)(
            jwtauth.Authenticator()(
                yourHandler(),
            ),
        ),
    )
}
```

### Web Application Integration

``` go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to web client
    tokenData := &jwtauth.TokenData{
        AccessToken:  "your-access-token",
        RefreshToken: "your-refresh-token",
        Domain:      "your-domain",
        Path:        "/",
        ExpiresAt:   time.Now().Add(24 * time.Hour),
        HttpOnly:    true,
    }
    
    jwtauth.SendTokensToWeb(w, tokenData, http.StatusOK)
}
```

### Mobile Application Integration

``` go
func handleMobileLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to mobile client
    tokenData := &jwtauth.TokenData{
        AccessToken:  "your-access-token",
        RefreshToken: "your-refresh-token",
        AdditionalFields: map[string]string{
            "user_id": "123",
            "role": "user",
        },
    }
    
    jwtauth.SendTokensToMobileApp(w, tokenData, http.StatusOK)
}
```

### Token Data Structure

The library provides a flexible TokenData structure that can be used to handle various authentication scenarios:

``` go
type TokenData struct {
    AccessToken      string            // JWT access token
    RefreshToken     string            // Refresh token for token renewal
    Domain           string            // Cookie domain (optional)
    Path             string            // Cookie path (optional)
    ExpiresAt        time.Time         // Token expiration time
    HttpOnly         bool              // HttpOnly flag for cookies
    AdditionalFields map[string]string // Additional data to be included in response
}
```

### Working with gRPC

``` go
func YourGrpcClientMethod(ctx context.Context) {
    // Add access token to gRPC metadata
    ctx, err := jwtauth.AddAccessTokenToMetadata(ctx)
    if err != nil {
        // Handle error
    }
    
    // Make your gRPC call with the updated context
    response, err := grpcClient.Method(ctx, request)
}
```

## Configuration

### Token Service Options

The token service can be initialized with various options:

``` go 
tokenService := jwtauth.New(
    "https://your-auth-server/.well-known/jwks.json",
)
```

### Cookie Settings

You can customize cookie settings when sending tokens:

``` go
jwtauth.SetTokenCookie(w, 
    "access_token",
    tokenValue,
    "your-domain",
    "/",
    time.Now().Add(24 * time.Hour),
    true,
)
```

## Error Handling

The library provides predefined errors for common scenarios:

``` go
switch err {
case jwtauth.ErrNoTokenFound:
    // Handle missing token
case jwtauth.ErrInvalidToken:
    // Handle invalid token
case jwt.ErrTokenExpired:
    // Handle expired token
}
```

## Security Considerations

- Always use HTTPS for production environments
- Set appropriate token expiration times
- Use HttpOnly cookies for web applications
- Implement refresh token rotation
- Keep your JWKS endpoint secure
- Regularly rotate your signing keys

## License

MIT License - see the LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For questions and support, please open an issue in the GitHub repository.