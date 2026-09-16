package webflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/tokenutil"
	"github.com/isklv/slogging"
)

type CookieConfig struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
}

type Flow struct {
	cfg         keycloak.Config
	client      *http.Client
	cookie      CookieConfig
	loginURL    string
	redirectURI string
}

func New(cfg keycloak.Config, cookie CookieConfig, loginURL, redirectURI string, client *http.Client) *Flow {
	if client == nil {
		client = http.DefaultClient
	}
	if cookie.Name == "" {
		cookie.Name = "kc_at"
	}
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	if cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteLaxMode
	}
	return &Flow{
		cfg:         cfg,
		client:      client,
		cookie:      cookie,
		loginURL:    loginURL,
		redirectURI: redirectURI,
	}
}

// PKCE holds a code verifier and code challenge pair according to RFC 7636.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

// GeneratePKCE generates a cryptographically random code verifier (32 random bytes, base64url encoded)
// and computes its SHA-256 code challenge for the S256 PKCE method.
func GeneratePKCE() (*PKCE, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes for PKCE: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

// GenerateState generates a cryptographically random state string for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthOption configures parameters for the authorization URL.
type AuthOption func(*url.Values)

// WithPKCEChallenge adds PKCE code_challenge and code_challenge_method=S256 to the auth URL.
func WithPKCEChallenge(challenge string) AuthOption {
	return func(v *url.Values) {
		if challenge != "" {
			v.Set("code_challenge", challenge)
			v.Set("code_challenge_method", "S256")
		}
	}
}

// WithScope overrides the default scopes ("openid profile email").
func WithScope(scope string) AuthOption {
	return func(v *url.Values) {
		if scope != "" {
			v.Set("scope", scope)
		}
	}
}

// AuthCodeURL builds the authorization redirect URL.
// Optional AuthOptions can be provided, such as WithPKCEChallenge.
func (f *Flow) AuthCodeURL(state string, opts ...AuthOption) string {
	authURL := f.cfg.Issuer() + "/protocol/openid-connect/auth"

	v := url.Values{}
	v.Set("client_id", f.cfg.ClientID)
	v.Set("response_type", "code")
	v.Set("redirect_uri", f.redirectURI)
	v.Set("scope", "openid profile email")
	if state != "" {
		v.Set("state", state)
	}

	for _, opt := range opts {
		opt(&v)
	}

	return authURL + "?" + v.Encode()
}

// AuthCodeURLWithPKCE is a convenience method that adds the S256 code challenge to the authorization URL.
func (f *Flow) AuthCodeURLWithPKCE(state, codeChallenge string) string {
	return f.AuthCodeURL(state, WithPKCEChallenge(codeChallenge))
}

// ExchangeOption configures parameters for code exchange.
type ExchangeOption func(*url.Values)

// WithCodeVerifier adds code_verifier to the token exchange request for PKCE validation.
func WithCodeVerifier(verifier string) ExchangeOption {
	return func(v *url.Values) {
		if verifier != "" {
			v.Set("code_verifier", verifier)
		}
	}
}

// ExchangeCode exchanges an authorization code for tokens at Keycloak's token endpoint.
// Supports optional ExchangeOptions, such as WithCodeVerifier.
func (f *Flow) ExchangeCode(ctx context.Context, code string, opts ...ExchangeOption) (*tokenutil.CommonToken, error) {
	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", f.cfg.ClientID)
	if f.cfg.ClientSecret != "" {
		form.Set("client_secret", f.cfg.ClientSecret)
	}
	form.Set("redirect_uri", f.redirectURI)

	for _, opt := range opts {
		opt(&form)
	}

	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	slogging.L(ctx).Debug("Request", slogging.RequestAttr(req)...)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	slogging.L(ctx).Debug("Response", slogging.ResponseAttr(resp, start)...)

	return tokenutil.ParseTokenResponse(resp)
}

// ExchangeCodeWithPKCE is a convenience method that includes the PKCE code_verifier in the exchange request.
func (f *Flow) ExchangeCodeWithPKCE(ctx context.Context, code, verifier string) (*tokenutil.CommonToken, error) {
	return f.ExchangeCode(ctx, code, WithCodeVerifier(verifier))
}

func (f *Flow) CookieConfig() CookieConfig { return f.cookie }
func (f *Flow) CookieName() string         { return f.cookie.Name }
func (f *Flow) LoginURL() string           { return f.loginURL }
