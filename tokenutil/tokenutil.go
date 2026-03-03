package tokenutil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CommonToken struct {
	AccessToken      string
	RefreshToken     string
	TokenType        string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	Scope            string
	IDToken          string
}

type wireTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	IDToken          string `json:"id_token"`
}

func ParseTokenResponse(resp *http.Response) (*CommonToken, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint: %s: %s", resp.Status, string(body))
	}

	var tr wireTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}

	now := time.Now()

	return &CommonToken{
		AccessToken:      tr.AccessToken,
		RefreshToken:     tr.RefreshToken,
		TokenType:        tr.TokenType,
		ExpiresAt:        now.Add(time.Duration(tr.ExpiresIn) * time.Second),
		RefreshExpiresAt: now.Add(time.Duration(tr.RefreshExpiresIn) * time.Second),
		Scope:            tr.Scope,
		IDToken:          tr.IDToken,
	}, nil
}
