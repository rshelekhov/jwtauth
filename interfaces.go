package jwtauth

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"net/http"
)

type (
	Extractor interface {
		ExtractTokenFromGRPC(ctx context.Context) (string, error)
		ExtractTokenFromHTTP(r *http.Request) (string, error)
		ExtractTokenFromCookies(r *http.Request) (string, error)
		ExtractRefreshTokenFromCookies(r *http.Request) (string, error)
	}

	ContextManager interface {
		FromContext(ctx context.Context) (string, bool)
		ToContext(ctx context.Context, value string) context.Context
	}

	TokenParser interface {
		ParseToken(appID, token string) (*jwt.Token, error)
		ExtractUserID(ctx context.Context, appID string) (string, error)
	}

	TokenSender interface {
		SendTokensToWeb(w http.ResponseWriter, resp *TokenResponse, httpStatus int)
		SendTokensToMobileApp(w http.ResponseWriter, resp *TokenResponse, httpStatus int)
	}

	Middleware interface {
		UnaryServerInterceptor() grpc.UnaryServerInterceptor
		HTTPMiddleware(next http.Handler) http.Handler
	}

	Manager interface {
		Extractor
		ContextManager
		TokenParser
		TokenSender
		Middleware
	}
)