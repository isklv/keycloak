package clientcred

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/isklv/keycloak"
	"github.com/isklv/keycloak/tokenutil"
)

type Token = tokenutil.CommonToken
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

type source struct {
	cfg    keycloak.Config
	client *http.Client

	mu  sync.Mutex
	tok *Token
}

func NewTokenSource(cfg keycloak.Config, client *http.Client) TokenSource {
	if client == nil {
		client = http.DefaultClient
	}
	return &source{cfg: cfg, client: client}
}

func (s *source) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if s.tok != nil && now.Before(s.tok.ExpiresAt.Add(-30*time.Second)) {
		return s.tok, nil
	}

	if s.tok != nil && s.tok.RefreshToken != "" && now.Before(s.tok.RefreshExpiresAt) {
		if err := s.refreshWithRefreshToken(ctx); err == nil {
			return s.tok, nil
		}
	}

	if err := s.fetchWithClientCredentials(ctx); err != nil {
		return nil, err
	}

	return s.tok, nil
}

func (s *source) fetchWithClientCredentials(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tok, err := tokenutil.ParseTokenResponse(resp)
	if err != nil {
		return err
	}

	s.tok = tok

	return nil
}

func (s *source) refreshWithRefreshToken(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	form.Set("refresh_token", s.tok.RefreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tok, err := tokenutil.ParseTokenResponse(resp)
	if err != nil {
		return err
	}

	s.tok = tok

	return nil
}
