package webflow

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/isklv/keycloak/tokenutil"
)

type Token = tokenutil.CommonToken

type UserTokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

type userSource struct {
	f   *Flow
	mu  sync.Mutex
	tok *Token
}

func NewUserTokenSource(f *Flow, initial *Token) UserTokenSource {
	return &userSource{f: f, tok: initial}
}

func (s *userSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if s.tok != nil && now.Before(s.tok.ExpiresAt.Add(-30*time.Second)) {
		return s.tok, nil
	}

	if s.tok != nil && s.tok.RefreshToken != "" && now.Before(s.tok.RefreshExpiresAt) {
		if err := s.refresh(ctx); err == nil {
			return s.tok, nil
		}
	}

	return nil, fmt.Errorf("Need login")
}

func (s *userSource) refresh(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", s.f.cfg.ClientID)
	if s.f.cfg.ClientSecret != "" {
		form.Set("client_secret", s.f.cfg.ClientSecret)
	}
	form.Set("refresh_token", s.tok.RefreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.f.cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.f.client.Do(req)
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
