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
		BackendAuthURL: "http://localhost:8080/auth",
		Realm:          "test",
	}

	tokenURL := cfg.TokenURL()
	expected := "http://localhost:8080/auth/realms/test/protocol/openid-connect/token"
	if tokenURL != expected {
		t.Errorf("Expected tokenURL '%s', got '%s'", expected, tokenURL)
	}
}

func TestConfig_JWKSURL(t *testing.T) {
	cfg := Config{
		BackendAuthURL: "http://localhost:8080/auth",
		Realm:          "test",
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

	// Note: Current implementation doesn't strip trailing slashes
	issuer := cfg.Issuer()
	if issuer != "http://localhost:8080/auth//realms/test" {
		t.Errorf("Expected issuer 'http://localhost:8080/auth//realms/test' (with double slash), got '%s'", issuer)
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
