package keycloak

import "strings"

type Config struct {
	// AuthURL is the base URL for the Keycloak server.
	// Used for both user-facing (issuer) and backend (token/JWKS) calls.
	AuthURL string

	// BackendAuthURL overrides AuthURL for server-to-server calls
	// (token endpoint, JWKS). Useful when Keycloak is behind a proxy
	// with different internal/external URLs. Empty = use AuthURL.
	BackendAuthURL string

	ClientID     string
	Realm        string
	RedirectURL  string // OAUTH
	ClientSecret string // confidential / client credentials

	// AuthorizedParties is a list of allowed azp (authorized party) values.
	// When empty (default), azp validation is skipped.
	// When non-empty, the token's azp claim must be one of the listed values.
	// Useful for multi-service setups or api2api integration where tokens
	// are issued to different clients.
	AuthorizedParties []string
}

// backendBase returns the base URL for backend calls (token, JWKS).
// Falls back to AuthURL if BackendAuthURL is not set.
func (c Config) backendBase() string {
	if c.BackendAuthURL != "" {
		return strings.TrimRight(c.BackendAuthURL, "/")
	}
	return strings.TrimRight(c.AuthURL, "/")
}

func (c Config) Issuer() string {
	return strings.TrimRight(c.AuthURL, "/") + "/realms/" + c.Realm
}

func (c Config) IssuerBackend() string {
	return c.backendBase() + "/realms/" + c.Realm
}

func (c Config) JWKSURL() string {
	return c.IssuerBackend() + "/protocol/openid-connect/certs"
}

func (c Config) TokenURL() string {
	return c.IssuerBackend() + "/protocol/openid-connect/token"
}
