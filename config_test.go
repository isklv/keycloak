package keycloak

import (
	"testing"
)

func TestConfig_Issuer(t *testing.T) {
	cfg := Config{
		AuthURL: "http://localhost:8080/auth",
		Realm:   "test",
	}

	issuer := cfg.Issuer()
	expected := "http://localhost:8080/auth/realms/test"
	if issuer != expected {
		t.Errorf("Expected issuer '%s', got '%s'", expected, issuer)
	}
}

func TestConfig_TokenURL(t *testing.T) {
	cfg := Config{
		AuthURL: "http://localhost:8080/auth",
		Realm:   "test",
	}

	tokenURL := cfg.TokenURL()
	expected := "http://localhost:8080/auth/realms/test/protocol/openid-connect/token"
	if tokenURL != expected {
		t.Errorf("Expected tokenURL '%s', got '%s'", expected, tokenURL)
	}
}

func TestConfig_BackendAuthURLFallback(t *testing.T) {
	t.Run("FallbackToAuthURL", func(t *testing.T) {
		cfg := Config{
			AuthURL: "http://public.example.com/auth",
			Realm:   "myrealm",
		}
		// BackendAuthURL not set — should fall back to AuthURL
		backend := cfg.IssuerBackend()
		expected := "http://public.example.com/auth/realms/myrealm"
		if backend != expected {
			t.Errorf("Expected backend '%s', got '%s'", expected, backend)
		}
	})

	t.Run("OverrideBackendAuthURL", func(t *testing.T) {
		cfg := Config{
			AuthURL:        "http://public.example.com/auth",
			BackendAuthURL: "http://internal-keycloak:8080",
			Realm:          "myrealm",
		}
		public := cfg.Issuer()
		backend := cfg.IssuerBackend()

		if public != "http://public.example.com/auth/realms/myrealm" {
			t.Errorf("Expected public issuer, got '%s'", public)
		}
		if backend != "http://internal-keycloak:8080/realms/myrealm" {
			t.Errorf("Expected internal backend, got '%s'", backend)
		}
	})
}

func TestConfig_JWKSURL(t *testing.T) {
	cfg := Config{
		AuthURL: "http://localhost:8080/auth",
		Realm:   "test",
	}

	jwksURL := cfg.JWKSURL()
	expected := "http://localhost:8080/auth/realms/test/protocol/openid-connect/certs"
	if jwksURL != expected {
		t.Errorf("Expected JWKSURL '%s', got '%s'", expected, jwksURL)
	}
}

func TestConfig_WithTrailingSlash(t *testing.T) {
	cfg := Config{
		AuthURL: "http://localhost:8080/auth/",
		Realm:   "test",
	}

	// Trailing slashes are trimmed
	issuer := cfg.Issuer()
	expected := "http://localhost:8080/auth/realms/test"
	if issuer != expected {
		t.Errorf("Expected issuer '%s', got '%s'", expected, issuer)
	}
}

func TestConfig_EmptyRealm(t *testing.T) {
	cfg := Config{
		AuthURL: "http://localhost:8080/auth",
		Realm:   "",
	}

	// Should still work, just with empty realm
	issuer := cfg.Issuer()
	if issuer != "http://localhost:8080/auth/realms/" {
		t.Errorf("Expected issuer 'http://localhost:8080/auth/realms/', got '%s'", issuer)
	}
}
