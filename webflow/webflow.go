package webflow

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isklv/keycloak"
	"github.com/isklv/keycloak/tokenutil"
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

func (f *Flow) AuthCodeURL(state string) string {
	authURL := f.cfg.Issuer() + "/protocol/openid-connect/auth"

	v := url.Values{}
	v.Set("client_id", f.cfg.ClientID)
	v.Set("response_type", "code")
	v.Set("redirect_uri", f.redirectURI)
	v.Set("scope", "openid profile email")
	if state != "" {
		v.Set("state", state)
	}

	return authURL + "?" + v.Encode()
}

func (f *Flow) ExchangeCode(ctx context.Context, code string) (*tokenutil.CommonToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", f.cfg.ClientID)
	if f.cfg.ClientSecret != "" {
		form.Set("client_secret", f.cfg.ClientSecret)
	}
	form.Set("redirect_uri", f.redirectURI)

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

func (f *Flow) CookieConfig() CookieConfig { return f.cookie }
func (f *Flow) CookieName() string         { return f.cookie.Name }
func (f *Flow) LoginURL() string           { return f.loginURL }
