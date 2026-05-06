package webflow

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/isklv/keycloak/v2"
)

func TestFlow_AuthCodeURL(t *testing.T) {
	cfg := keycloak.Config{
		AuthURL:        "http://localhost:8080/auth",
		BackendAuthURL: "http://localhost:8080/auth",
		Realm:          "test",
		ClientID:       "web",
	}

	flow := New(cfg, CookieConfig{}, "/login", "http://localhost:3000/callback", nil)

	t.Run("GeneratesValidURL", func(t *testing.T) {
		u := flow.AuthCodeURL("test-state")

		if u == "" {
			t.Error("Expected non-empty URL")
		}

		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("Invalid URL: %v", err)
		}

		if parsed.Scheme != "http" {
			t.Errorf("Expected scheme http, got %s", parsed.Scheme)
		}

		if parsed.Host != "localhost:8080" {
			t.Errorf("Expected host localhost:8080, got %s", parsed.Host)
		}

		if parsed.Path != "/auth/realms/test/protocol/openid-connect/auth" {
			t.Errorf("Expected path /auth/realms/test/protocol/openid-connect/auth, got %s", parsed.Path)
		}

		// Check query params
		q := parsed.Query()
		if q.Get("client_id") != "web" {
			t.Errorf("Expected client_id=web, got %s", q.Get("client_id"))
		}
		if q.Get("response_type") != "code" {
			t.Errorf("Expected response_type=code, got %s", q.Get("response_type"))
		}
		if q.Get("redirect_uri") != "http://localhost:3000/callback" {
			t.Errorf("Expected redirect_uri=http://localhost:3000/callback, got %s", q.Get("redirect_uri"))
		}
		if q.Get("scope") != "openid profile email" {
			t.Errorf("Expected scope='openid profile email', got %s", q.Get("scope"))
		}
		if q.Get("state") != "test-state" {
			t.Errorf("Expected state=test-state, got %s", q.Get("state"))
		}
	})

	t.Run("EmptyState", func(t *testing.T) {
		u := flow.AuthCodeURL("")
		parsed, _ := url.Parse(u)
		if parsed.Query().Get("state") != "" {
			t.Error("Expected empty state when not provided")
		}
	})
}

func TestFlow_ExchangeCode(t *testing.T) {
	// Setup test server
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("grant_type=authorization_code")) {
			t.Error("Expected grant_type=authorization_code")
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "refresh-abc123",
			"scope": "openid profile email"
		}`))
	}))
	defer tokenEndpoint.Close()

	cfg := keycloak.Config{
		AuthURL:        tokenEndpoint.URL,
		BackendAuthURL: tokenEndpoint.URL,
		Realm:          "test",
		ClientID:       "web",
		ClientSecret:   "secret",
	}

	flow := New(cfg, CookieConfig{}, "/login", "http://localhost:3000/callback", nil)

	t.Run("ValidCode", func(t *testing.T) {
		token, err := flow.ExchangeCode(context.Background(), "auth-code-123")
		if err != nil {
			t.Fatalf("ExchangeCode failed: %v", err)
		}

		if token.AccessToken == "" {
			t.Error("Expected access token")
		}
		if token.TokenType != "Bearer" {
			t.Errorf("Expected token_type=Bearer, got %s", token.TokenType)
		}
		if token.RefreshToken != "refresh-abc123" {
			t.Errorf("Expected refresh_token, got %s", token.RefreshToken)
		}
		if token.ExpiresAt.IsZero() {
			t.Error("Expected ExpiresAt to be set")
		}
	})

	t.Run("EmptyCode", func(t *testing.T) {
		_, err := flow.ExchangeCode(context.Background(), "")
		if err == nil {
			t.Error("Expected error for empty code")
		}
	})
}

func TestFlow_CookieConfig(t *testing.T) {
	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}

	// Test defaults
	flow := New(cfg, CookieConfig{}, "/login", "http://localhost/callback", nil)
	c := flow.CookieConfig()

	if c.Name != "kc_at" {
		t.Errorf("Expected default cookie name 'kc_at', got '%s'", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Expected default cookie path '/', got '%s'", c.Path)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected default SameSite=Lax, got %v", c.SameSite)
	}

	// Test custom config
	customCfg := CookieConfig{
		Name:     "custom_cookie",
		Path:     "/api",
		Domain:   "example.com",
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	flow2 := New(cfg, customCfg, "/login", "http://localhost/callback", nil)
	c2 := flow2.CookieConfig()

	if c2.Name != "custom_cookie" {
		t.Errorf("Expected cookie name 'custom_cookie', got '%s'", c2.Name)
	}
	if c2.Domain != "example.com" {
		t.Errorf("Expected cookie domain 'example.com', got '%s'", c2.Domain)
	}
	if !c2.Secure {
		t.Error("Expected cookie to be Secure")
	}
	if !c2.HTTPOnly {
		t.Error("Expected cookie to be HTTPOnly")
	}
	if c2.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite=Strict, got %v", c2.SameSite)
	}
}

func TestFlow_Accessors(t *testing.T) {
	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}

	flow := New(cfg, CookieConfig{}, "/login", "http://localhost/callback", nil)

	if flow.CookieName() != "kc_at" {
		t.Errorf("Expected CookieName='kc_at', got '%s'", flow.CookieName())
	}
	if flow.LoginURL() != "/login" {
		t.Errorf("Expected LoginURL='/login', got '%s'", flow.LoginURL())
	}
}
