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

// NewServiceWithKeyfunc creates an auth.Service with a custom keyfunc.Keyfunc (useful for testing or custom JWKS).
func NewServiceWithKeyfunc(cfg keycloak.Config, jwks keyfunc.Keyfunc) *Service {
	return &Service{
		cfg:  cfg,
		jwks: jwks,
	}
}

// ParseClaimsUnverified extracts and parses Claims from raw JWT token without signature validation.
func ParseClaimsUnverified(raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrUnauthorized
	}
	parser := jwt.NewParser()
	claims := &Claims{}
	_, _, err := parser.ParseUnverified(raw, claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

// ParseTokenUnverified parses claims on the service instance without JWKS signature validation.
func (s *Service) ParseTokenUnverified(raw string) (*Claims, error) {
	return ParseClaimsUnverified(raw)
}

var (
	ErrInvalidToken  = errors.New("invalid token")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrInvalidAZP    = errors.New("invalid authorized party (azp)")
)

func (s *Service) ParseAndValidateToken(ctx context.Context, raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrUnauthorized
	}

	if s.jwks == nil {
		return s.ParseTokenUnverified(raw)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer()),
	)

	token, err := parser.ParseWithClaims(raw, &Claims{}, s.jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate azp (authorized party) if AuthorizedParties is configured.
	// When empty (default), azp validation is skipped — useful for api2api
	// integrations where tokens are issued to different clients.
	if len(s.cfg.AuthorizedParties) > 0 {
		if claims.AuthorizedParty == "" {
			return nil, fmt.Errorf("%w: missing azp claim in token", ErrInvalidAZP)
		}
		allowed := false
		for _, azp := range s.cfg.AuthorizedParties {
			if azp == claims.AuthorizedParty {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: expected one of %v, got %q", ErrInvalidAZP, s.cfg.AuthorizedParties, claims.AuthorizedParty)
		}
	}

	return claims, nil
}
