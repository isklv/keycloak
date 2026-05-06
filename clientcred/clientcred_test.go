package clientcred

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/isklv/keycloak/v2"
)

func TestTokenSource_Caching(t *testing.T) {
	var requestCount int

	// Setup test server
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Return mock token response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMiLCJhenAiOiJzdmMifQ.signature",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
	}))
	defer tokenEndpoint.Close()

	cfg := keycloak.Config{
		AuthURL:        tokenEndpoint.URL,
		BackendAuthURL: tokenEndpoint.URL,
		Realm:          "test",
		ClientID:       "svc",
		ClientSecret:   "secret",
	}

	src := NewTokenSource(cfg, nil)

	// First request should hit the server
	tok1, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("First Token() failed: %v", err)
	}
	if tok1.AccessToken != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMiLCJhenAiOiJzdmMifQ.signature" {
		t.Errorf("Unexpected access token: %s", tok1.AccessToken)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Second request should use cache (within 30s buffer)
	tok2, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Second Token() failed: %v", err)
	}
	if tok2 != tok1 {
		t.Error("Expected cached token to be same instance")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request (cached), got %d", requestCount)
	}
}

func TestTokenSource_RefreshWithRefreshToken(t *testing.T) {
	var callCount int

	// Setup test server that returns refresh token
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}

		grantType := r.FormValue("grant_type")

		if grantType == "client_credentials" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "access-1",
				"token_type": "Bearer",
				"expires_in": 1,
				"refresh_token": "refresh-1",
				"refresh_expires_in": 3600
			}`))
		} else if grantType == "refresh_token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "access-2",
				"token_type": "Bearer",
				"expires_in": 3600,
				"refresh_token": "refresh-2"
			}`))
		} else {
			t.Errorf("Unexpected grant_type: %s", grantType)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer tokenEndpoint.Close()

	cfg := keycloak.Config{
		AuthURL:        tokenEndpoint.URL,
		BackendAuthURL: tokenEndpoint.URL,
		Realm:          "test",
		ClientID:       "svc",
		ClientSecret:   "secret",
	}

	src := NewTokenSource(cfg, nil)

	// Get initial token
	tok1, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("First Token() failed: %v", err)
	}
	if tok1.AccessToken != "access-1" {
		t.Errorf("Expected access-1, got %s", tok1.AccessToken)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}

	// Wait for token to expire (1s + buffer)
	time.Sleep(2 * time.Second)

	// Next request should refresh
	tok2, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Second Token() failed: %v", err)
	}
	if tok2.AccessToken != "access-2" {
		t.Errorf("Expected access-2 (refreshed), got %s", tok2.AccessToken)
	}
	if callCount != 2 {
		t.Errorf("Expected 2 calls (1 initial + 1 refresh), got %d", callCount)
	}
}

func TestTokenSource_Concurrent(t *testing.T) {
	var mu sync.Mutex
	var callCount int

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		currentCall := callCount
		mu.Unlock()

		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "token-` + string(rune('0'+currentCall)) + `",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
	}))
	defer tokenEndpoint.Close()

	cfg := keycloak.Config{
		AuthURL:        tokenEndpoint.URL,
		BackendAuthURL: tokenEndpoint.URL,
		Realm:          "test",
		ClientID:       "svc",
		ClientSecret:   "secret",
	}

	src := NewTokenSource(cfg, nil)

	// Make 10 concurrent requests
	var wg sync.WaitGroup
	results := make([]string, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			if err != nil {
				t.Errorf("Token() failed: %v", err)
				return
			}
			results[idx] = tok.AccessToken
		}(i)
	}
	wg.Wait()

	// All should get the same token (first one)
	for i, result := range results {
		if result != "token-1" {
			t.Errorf("Result %d expected 'token-1', got '%s'", i, result)
		}
	}

	if callCount != 1 {
		t.Errorf("Expected 1 API call (due to caching), got %d", callCount)
	}
}

func TestTokenSource_CustomClient(t *testing.T) {
	var clientUsed bool

	customTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		clientUsed = true
		return http.DefaultTransport.RoundTrip(r)
	})

	customClient := &http.Client{
		Transport: customTransport,
	}

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
	}))
	defer tokenEndpoint.Close()

	cfg := keycloak.Config{
		AuthURL:        tokenEndpoint.URL,
		BackendAuthURL: tokenEndpoint.URL,
		Realm:          "test",
		ClientID:       "svc",
		ClientSecret:   "secret",
	}

	src := NewTokenSource(cfg, customClient)

	_, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}

	if !clientUsed {
		t.Error("Expected custom client to be used")
	}
}

// roundTripperFunc is an adapter to convert a function to a roundTripper
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rt roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}
