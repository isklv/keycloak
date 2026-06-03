package auth

import (
	"context"
	"errors"
	"fmt"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/isklv/keycloak/v2"
)

type Service struct {
	cfg  keycloak.Config
	jwks keyfunc.Keyfunc
}

func NewService(ctx context.Context, cfg keycloak.Config) (*Service, error) {
	jwks, err := keyfunc.NewDefault([]string{cfg.JWKSURL()})
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:  cfg,
		jwks: jwks,
	}, nil
}

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrInvalidAudience = errors.New("invalid audience")
	ErrInvalidAZP      = errors.New("invalid authorized party (azp)")
)

func (s *Service) ParseAndValidateToken(ctx context.Context, raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrUnauthorized
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer()),
		jwt.WithAudience(s.cfg.ClientID),
	)

	token, err := parser.ParseWithClaims(raw, &Claims{}, s.jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate azp (authorized party) — must match our client ID
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != s.cfg.ClientID {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrInvalidAZP, s.cfg.ClientID, claims.AuthorizedParty)
	}

	return claims, nil
}
