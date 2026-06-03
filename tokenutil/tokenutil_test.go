package tokenutil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTokenResponse(t *testing.T) {
	t.Run("ValidResponse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
				"token_type": "Bearer",
				"expires_in": 3600,
				"refresh_token": "refresh-token-123",
				"scope": "openid profile email",
				"refresh_expires_in": 86400
			}`))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get test response: %v", err)
		}
		defer resp.Body.Close()

		token, err := ParseTokenResponse(resp)
		if err != nil {
			t.Fatalf("ParseTokenResponse failed: %v", err)
		}

		if token.AccessToken != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" {
			t.Errorf("Expected access token, got '%s'", token.AccessToken)
		}
		if token.TokenType != "Bearer" {
			t.Errorf("Expected token_type='Bearer', got '%s'", token.TokenType)
		}
		if token.RefreshToken != "refresh-token-123" {
			t.Errorf("Expected refresh_token, got '%s'", token.RefreshToken)
		}
		if token.Scope != "openid profile email" {
			t.Errorf("Expected scope='openid profile email', got '%s'", token.Scope)
		}

		// Check ExpiresAt is set correctly
		if token.ExpiresAt.IsZero() {
			t.Error("Expected ExpiresAt to be set")
		}
		expectedExp := time.Now().Add(3600 * time.Second)
		if token.ExpiresAt.After(expectedExp.Add(time.Minute)) || token.ExpiresAt.Before(expectedExp.Add(-time.Minute)) {
			t.Errorf("Expected ExpiresAt around %v, got %v", expectedExp, token.ExpiresAt)
		}

		// Check RefreshExpiresAt
		if token.RefreshExpiresAt.IsZero() {
			t.Error("Expected RefreshExpiresAt to be set")
		}
		expectedRefresh := time.Now().Add(86400 * time.Second)
		if token.RefreshExpiresAt.After(expectedRefresh.Add(time.Minute)) || token.RefreshExpiresAt.Before(expectedRefresh.Add(-time.Minute)) {
			t.Errorf("Expected RefreshExpiresAt around %v, got %v", expectedRefresh, token.RefreshExpiresAt)
		}
	})

	t.Run("MissingRequiredFields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"token_type": "Bearer"}`))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get test response: %v", err)
		}
		defer resp.Body.Close()

		_, err = ParseTokenResponse(resp)
		if err == nil {
			t.Error("Expected error for missing access_token")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`invalid json`))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get test response: %v", err)
		}
		defer resp.Body.Close()

		_, err = ParseTokenResponse(resp)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(``))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get test response: %v", err)
		}
		defer resp.Body.Close()

		_, err = ParseTokenResponse(resp)
		if err == nil {
			t.Error("Expected error for empty body")
		}
	})

	t.Run("ErrorStatusCode", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "invalid_grant", "error_description": "Invalid refresh token"}`))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to get test response: %v", err)
		}
		defer resp.Body.Close()

		_, err = ParseTokenResponse(resp)
		if err == nil {
			t.Error("Expected error for non-2xx status")
		}
	})
}

func TestParseTokenResponse_ReadError(t *testing.T) {
	// Simulate a response that errors on Read
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(&errorReader{}),
	}

	_, err := ParseTokenResponse(resp)
	if err == nil {
		t.Error("Expected error when reading body")
	}
}

// errorReader always returns an error
type errorReader struct{}
func (e *errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestMaskToken(t *testing.T) {
	t.Run("LongToken", func(t *testing.T) {
		token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4JIPj"
		masked := MaskToken(token)
		if masked == token {
			t.Error("Masked token should not equal original")
		}
		if !strings.HasPrefix(masked, token[:10]) {
			t.Errorf("Masked token should start with first 10 chars, got: %s", masked)
		}
		if !strings.HasSuffix(masked, token[len(token)-6:]) {
			t.Errorf("Masked token should end with last 6 chars, got: %s", masked)
		}
	})

	t.Run("ShortToken", func(t *testing.T) {
		token := "short"
		masked := MaskToken(token)
		if masked != "<token>" {
			t.Errorf("Short token should be '<token>', got: %s", masked)
		}
	})

	t.Run("EmptyToken", func(t *testing.T) {
		masked := MaskToken("")
		if masked != "<token>" {
			t.Errorf("Empty token should be '<token>', got: %s", masked)
		}
	})
}


