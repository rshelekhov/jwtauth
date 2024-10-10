# JWT Authentication Middleware Library

This library provides middleware for verifying and authenticating JSON Web Tokens (JWT) in HTTP requests. It offers flexible token extraction methods from request headers, cookies, and query parameters, as well as utilities for handling refresh tokens, parsing token claims, and managing JWT validation.

## Features

- JWT Verification Middleware: Automatically validates JWTs from requests.
- Flexible Token Sources: Extracts tokens from headers, cookies, or query parameters.
- Token Claims Parsing: Retrieves claims from valid tokens.
- Support for Refresh Tokens: Handles refresh tokens via headers or cookies.
- Token Validation Caching: Utilizes in-memory caching for efficient token validation with JWKS.
