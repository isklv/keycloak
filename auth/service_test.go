package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/isklv/keycloak/v2"
)

type testJWKSServer struct {
	server  *httptest.Server
	privKey *rsa.PrivateKey
	keyID   string
}

func newTestJWKSServer(t *testing.T) *testJWKSServer {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	keyID := "test-key-id"

	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.PublicKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksJSON := fmt.Sprintf(`{
		"keys": [
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": %q,
				"n": %q,
				"e": %q
			}
		]
	}`, keyID, nStr, eStr)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))

	t.Cleanup(func() {
		server.Close()
	})

	return &testJWKSServer{
		server:  server,
		privKey: privKey,
		keyID:   keyID,
	}
}

func (s *testJWKSServer) signToken(t *testing.T, claims *Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return signed
}

func TestService_ParseAndValidateToken(t *testing.T) {
	jwks := newTestJWKSServer(t)

	cfg := keycloak.Config{
		AuthURL: jwks.server.URL,
		Realm:   "test-realm",
	}

	svc, err := NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	t.Run("EmptyToken", func(t *testing.T) {
		_, err := svc.ParseAndValidateToken(context.Background(), "")
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("Expected ErrUnauthorized, got: %v", err)
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := svc.ParseAndValidateToken(context.Background(), "invalid.token.format")
		if err == nil {
			t.Error("Expected error for invalid token format")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected ErrInvalidToken, got: %v", err)
		}
	})

	t.Run("ValidToken", func(t *testing.T) {
		claims := &Claims{
			PreferredUsername: "john_doe",
			Email:             "john@example.com",
			AuthorizedParty:   "my-client",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				Subject:   "user-123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		claims.RealmAccess.Roles = []string{"admin", "user"}

		rawToken := jwks.signToken(t, claims)

		parsed, err := svc.ParseAndValidateToken(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("Expected token to be valid, got: %v", err)
		}

		if parsed.PreferredUsername != "john_doe" {
			t.Errorf("Expected username john_doe, got: %s", parsed.PreferredUsername)
		}
		if parsed.Email != "john@example.com" {
			t.Errorf("Expected email john@example.com, got: %s", parsed.Email)
		}
		if !parsed.HasRealmRole("admin") {
			t.Error("Expected admin role to be present")
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		claims := &Claims{
			PreferredUsername: "expired_user",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
		}

		rawToken := jwks.signToken(t, claims)

		_, err := svc.ParseAndValidateToken(context.Background(), rawToken)
		if err == nil {
			t.Error("Expected error for expired token, got nil")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected ErrInvalidToken, got: %v", err)
		}
	})

	t.Run("WrongIssuer", func(t *testing.T) {
		claims := &Claims{
			PreferredUsername: "user",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "http://wrong-issuer.com/realms/other",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}

		rawToken := jwks.signToken(t, claims)

		_, err := svc.ParseAndValidateToken(context.Background(), rawToken)
		if err == nil {
			t.Error("Expected error for wrong issuer, got nil")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected ErrInvalidToken, got: %v", err)
		}
	})

	t.Run("WrongSignature", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		claims := &Claims{
			PreferredUsername: "hacker",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = jwks.keyID
		signed, err := token.SignedString(otherKey)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		_, err = svc.ParseAndValidateToken(context.Background(), signed)
		if err == nil {
			t.Error("Expected signature verification failure, got nil")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected ErrInvalidToken, got: %v", err)
		}
	})
}

func TestService_ParseAndValidateToken_AZPValidation(t *testing.T) {
	jwks := newTestJWKSServer(t)

	t.Run("EmptyAuthorizedPartiesSkipsValidation", func(t *testing.T) {
		cfg := keycloak.Config{
			AuthURL: jwks.server.URL,
			Realm:   "test-realm",
		}
		svc, err := NewService(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		claims := &Claims{
			AuthorizedParty: "any-client",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		rawToken := jwks.signToken(t, claims)

		parsed, err := svc.ParseAndValidateToken(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("Expected token to be valid when AuthorizedParties is empty, got: %v", err)
		}
		if parsed.AuthorizedParty != "any-client" {
			t.Errorf("Expected azp=any-client, got: %s", parsed.AuthorizedParty)
		}
	})

	t.Run("AZPInAllowedList", func(t *testing.T) {
		cfg := keycloak.Config{
			AuthURL:           jwks.server.URL,
			Realm:             "test-realm",
			AuthorizedParties: []string{"svc", "frontend"},
		}
		svc, err := NewService(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		claims := &Claims{
			AuthorizedParty: "svc",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		rawToken := jwks.signToken(t, claims)

		parsed, err := svc.ParseAndValidateToken(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("Expected valid token for allowed azp, got: %v", err)
		}
		if parsed.AuthorizedParty != "svc" {
			t.Errorf("Expected azp=svc, got: %s", parsed.AuthorizedParty)
		}
	})

	t.Run("AZPNotInAllowedList", func(t *testing.T) {
		cfg := keycloak.Config{
			AuthURL:           jwks.server.URL,
			Realm:             "test-realm",
			AuthorizedParties: []string{"svc", "frontend"},
		}
		svc, err := NewService(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		claims := &Claims{
			AuthorizedParty: "untrusted-client",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		rawToken := jwks.signToken(t, claims)

		_, err = svc.ParseAndValidateToken(context.Background(), rawToken)
		if err == nil {
			t.Error("Expected error for disallowed azp, got nil")
		}
		if !errors.Is(err, ErrInvalidAZP) {
			t.Errorf("Expected ErrInvalidAZP, got: %v", err)
		}
	})

	t.Run("AZPMissingWhenConfigured", func(t *testing.T) {
		cfg := keycloak.Config{
			AuthURL:           jwks.server.URL,
			Realm:             "test-realm",
			AuthorizedParties: []string{"svc", "frontend"},
		}
		svc, err := NewService(context.Background(), cfg)
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		// Token without azp
		claims := &Claims{
			AuthorizedParty: "",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		rawToken := jwks.signToken(t, claims)

		_, err = svc.ParseAndValidateToken(context.Background(), rawToken)
		if err == nil {
			t.Error("Expected error for missing azp when AuthorizedParties is configured, got nil")
		}
		if !errors.Is(err, ErrInvalidAZP) {
			t.Errorf("Expected ErrInvalidAZP, got: %v", err)
		}
	})
}

func TestClaims_HasRealmRole(t *testing.T) {
	c := &Claims{
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"admin", "user", "api_v1"},
		},
	}

	t.Run("HasRole", func(t *testing.T) {
		if !c.HasRealmRole("admin") {
			t.Error("Expected to have admin role")
		}
	})

	t.Run("MissingRole", func(t *testing.T) {
		if c.HasRealmRole("superadmin") {
			t.Error("Expected not to have superadmin role")
		}
	})

	t.Run("HasAnyRealmRole", func(t *testing.T) {
		if !c.HasAnyRealmRole("superadmin", "api_v1", "owner") {
			t.Error("Expected to have api_v1 role")
		}
	})

	t.Run("HasAnyRealmRoleNoneMatch", func(t *testing.T) {
		if c.HasAnyRealmRole("owner", "superadmin") {
			t.Error("Expected no match")
		}
	})
}

func TestClaims_HasClientRole(t *testing.T) {
	c := &Claims{
		ResourceAccess: map[string]struct {
			Roles []string `json:"roles"`
		}{
			"web": {
				Roles: []string{"read", "write"},
			},
			"api": {
				Roles: []string{"admin"},
			},
		},
	}

	t.Run("HasClientRole", func(t *testing.T) {
		if !c.HasClientRole("web", "read") {
			t.Error("Expected to have read role in web client")
		}
	})

	t.Run("WrongClient", func(t *testing.T) {
		if c.HasClientRole("web", "admin") {
			t.Error("Expected not to have admin role in web client")
		}
	})

	t.Run("MissingClient", func(t *testing.T) {
		if c.HasClientRole("nonexistent", "admin") {
			t.Error("Expected not to have roles in nonexistent client")
		}
	})

	t.Run("HasAnyClientRole", func(t *testing.T) {
		if !c.HasAnyClientRole("web", "write", "delete", "update") {
			t.Error("Expected to have write role")
		}
	})
}

func TestClaims_AuthorizedParty(t *testing.T) {
	c := &Claims{
		AuthorizedParty: "svc",
	}

	if c.AuthorizedParty != "svc" {
		t.Errorf("Expected azp=svc, got: %s", c.AuthorizedParty)
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()

	// Empty context
	claims, ok := FromContext(ctx)
	if ok || claims != nil {
		t.Errorf("Expected nil, false for empty context, got: %v, %v", claims, ok)
	}

	// Context with claims
	testClaims := &Claims{PreferredUsername: "alice"}
	ctxWithClaims := WithClaims(ctx, testClaims)
	claims, ok = FromContext(ctxWithClaims)
	if !ok || claims == nil || claims.PreferredUsername != "alice" {
		t.Errorf("Expected alice in claims, got: %v, %v", claims, ok)
	}
}

func TestNewService_Error(t *testing.T) {
	// Invalid JWKS URL syntax causes keyfunc.NewDefault to error
	cfg := keycloak.Config{
		AuthURL: "://invalid-url",
	}
	_, err := NewService(context.Background(), cfg)
	if err == nil {
		t.Error("Expected error for invalid JWKS URL, got nil")
	}
}
