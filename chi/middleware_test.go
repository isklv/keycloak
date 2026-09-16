package chi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/webflow"
)

type testJWKSServer struct {
	server  *httptest.Server
	privKey *rsa.PrivateKey
	keyID   string
}

func newTestJWKSServer(t *testing.T) *testJWKSServer {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	keyID := "test-key-id"

	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.PublicKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksJSON := fmt.Sprintf(`{
		"keys": [
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": %q,
				"n": %q,
				"e": %q
			}
		]
	}`, keyID, nStr, eStr)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))

	t.Cleanup(func() {
		server.Close()
	})

	return &testJWKSServer{
		server:  server,
		privKey: privKey,
		keyID:   keyID,
	}
}

func (s *testJWKSServer) signToken(t *testing.T, claims *auth.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return signed
}

func TestMiddleware_Auth(t *testing.T) {
	jwks := newTestJWKSServer(t)

	cfg := keycloak.Config{
		AuthURL:  jwks.server.URL,
		Realm:    "test",
		ClientID: "web",
	}

	as, err := auth.NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
	mw := New(as, cfg, flow)

	t.Run("RedirectsWhenNoCookie", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.Auth()(handler)

		req := httptest.NewRequest("GET", "/protected", nil)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/login") {
			t.Errorf("Expected redirect to /login, got %s", location)
		}
		if !strings.Contains(location, "return=%2Fprotected") {
			t.Errorf("Expected return param, got %s", location)
		}
	})

	t.Run("RedirectsAndClearsCookieWhenInvalidToken", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.Auth()(handler)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.AddCookie(&http.Cookie{Name: "kc_at", Value: "invalid-garbage-token"})
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", w.Code)
		}

		// Cookie should be cleared
		cookies := w.Result().Cookies()
		var cleared bool
		for _, c := range cookies {
			if c.Name == "kc_at" && c.MaxAge == -1 {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Error("Expected auth cookie to be cleared on invalid token")
		}
	})

	t.Run("PassesWithValidCookie", func(t *testing.T) {
		claims := &auth.Claims{
			PreferredUsername: "alice",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				Subject:   "user-alice",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		validToken := jwks.signToken(t, claims)

		var capturedClaims *auth.Claims
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := auth.FromContext(r.Context())
			if ok {
				capturedClaims = c
			}
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.Auth()(handler)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.AddCookie(&http.Cookie{Name: "kc_at", Value: validToken})
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
		if capturedClaims == nil || capturedClaims.PreferredUsername != "alice" {
			t.Errorf("Expected claims for alice in context, got: %v", capturedClaims)
		}
	})
}

func TestMiddleware_AuthBearer(t *testing.T) {
	jwks := newTestJWKSServer(t)

	cfg := keycloak.Config{
		AuthURL:  jwks.server.URL,
		Realm:    "test",
		ClientID: "web",
	}

	as, err := auth.NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	flow := webflow.New(cfg, webflow.CookieConfig{}, "/login", "http://localhost/callback", nil)
	mw := New(as, cfg, flow)

	t.Run("MissingAuthorizationHeader", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.AuthBearer()(handler)

		req := httptest.NewRequest("GET", "/api", nil)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("InvalidBearerFormat", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.AuthBearer()(handler)

		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Invalid token123")
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("ValidBearerFormat", func(t *testing.T) {
		claims := &auth.Claims{
			PreferredUsername: "bob",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		validToken := jwks.signToken(t, claims)

		var capturedClaims *auth.Claims
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := auth.FromContext(r.Context())
			if ok {
				capturedClaims = c
			}
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.AuthBearer()(handler)

		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
		if capturedClaims == nil || capturedClaims.PreferredUsername != "bob" {
			t.Errorf("Expected claims for bob in context, got: %v", capturedClaims)
		}
	})

	t.Run("ExpiredBearerToken", func(t *testing.T) {
		claims := &auth.Claims{
			PreferredUsername: "expired_bob",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.Issuer(),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			},
		}
		expiredToken := jwks.signToken(t, claims)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.AuthBearer()(handler)

		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for expired token, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "invalid or expired token") {
			t.Errorf("Expected error message about invalid or expired token, got: %s", w.Body.String())
		}
	})
}

func TestMiddleware_RequireRealmRole(t *testing.T) {
	mockAS := &auth.Service{}

	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}

	flow := webflow.New(cfg, webflow.CookieConfig{}, "/login", "http://localhost/callback", nil)
	mw := New(mockAS, cfg, flow)

	t.Run("NoClaimsInContext", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireRealmRole("admin")(handler)

		req := httptest.NewRequest("GET", "/admin", nil)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("WithMatchingClaim", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireRealmRole("admin")(handler)

		req := httptest.NewRequest("GET", "/admin", nil)
		claims := &auth.Claims{
			RealmAccess: struct {
				Roles []string `json:"roles"`
			}{
				Roles: []string{"admin", "user"},
			},
		}
		req = req.WithContext(auth.WithClaims(req.Context(), claims))
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
	})

	t.Run("MissingRequiredRole", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireAnyRealmRole("admin", "manager")(handler)

		req := httptest.NewRequest("GET", "/admin", nil)
		claims := &auth.Claims{
			RealmAccess: struct {
				Roles []string `json:"roles"`
			}{
				Roles: []string{"user", "viewer"},
			},
		}
		req = req.WithContext(auth.WithClaims(req.Context(), claims))
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "forbidden — missing required realm role: admin, manager") {
			t.Errorf("Unexpected error body: %s", w.Body.String())
		}
	})
}

func TestMiddleware_RequireAnyClientRole(t *testing.T) {
	mockAS := &auth.Service{}

	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}

	flow := webflow.New(cfg, webflow.CookieConfig{}, "/login", "http://localhost/callback", nil)
	mw := New(mockAS, cfg, flow)

	t.Run("NoClaimsInContext", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireAnyClientRole("read", "write")(handler)

		req := httptest.NewRequest("GET", "/data", nil)
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden (no claims in context), got %d", w.Code)
		}
	})

	t.Run("WithMatchingClientRole", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireClientRole("read")(handler)

		req := httptest.NewRequest("GET", "/data", nil)
		claims := &auth.Claims{
			ResourceAccess: map[string]struct {
				Roles []string `json:"roles"`
			}{
				"web": {
					Roles: []string{"read", "delete"},
				},
			},
		}
		req = req.WithContext(auth.WithClaims(req.Context(), claims))
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
	})

	t.Run("MissingClientRole", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		protected := mw.RequireAnyClientRole("write", "admin")(handler)

		req := httptest.NewRequest("GET", "/data", nil)
		claims := &auth.Claims{
			ResourceAccess: map[string]struct {
				Roles []string `json:"roles"`
			}{
				"web": {
					Roles: []string{"read"},
				},
			},
		}
		req = req.WithContext(auth.WithClaims(req.Context(), claims))
		w := httptest.NewRecorder()

		protected.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "forbidden — missing required client role [web]: write, admin (have: read)") {
			t.Errorf("Unexpected error body: %s", w.Body.String())
		}
	})
}

func TestHandler_HandleCallback(t *testing.T) {
	t.Run("MissingCode", func(t *testing.T) {
		cfg := keycloak.Config{Realm: "test", ClientID: "web"}
		flow := webflow.New(cfg, webflow.CookieConfig{}, "/login", "/callback", nil)
		h := NewHandler(flow, nil, "/")
		req := httptest.NewRequest("GET", "/callback", nil)
		w := httptest.NewRecorder()

		h.HandleCallback(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "missing code") {
			t.Errorf("Expected 'missing code' body, got %s", w.Body.String())
		}
	})

	t.Run("ExchangeCodeError", func(t *testing.T) {
		// Token endpoint that returns error
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
		}))
		defer server.Close()

		cfg := keycloak.Config{
			AuthURL:  server.URL,
			Realm:    "test",
			ClientID: "web",
		}
		flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
		h := NewHandler(flow, nil, "/dashboard")

		req := httptest.NewRequest("GET", "/callback?code=badcode", nil)
		w := httptest.NewRecorder()

		h.HandleCallback(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500 Internal Server Error, got %d", w.Code)
		}
	})

	t.Run("SuccessfulCallback", func(t *testing.T) {
		// Mock token endpoint returning valid JSON
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "mock-access-token-xyz",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		}))
		defer server.Close()

		cfg := keycloak.Config{
			AuthURL:  server.URL,
			Realm:    "test",
			ClientID: "web",
		}
		flow := webflow.New(cfg, webflow.CookieConfig{
			Name:     "kc_at",
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: http.SameSiteLaxMode,
		}, "/login", "http://localhost/callback", nil)

		h := NewHandler(flow, nil, "/dashboard")

		req := httptest.NewRequest("GET", "/callback?code=goodcode", nil)
		w := httptest.NewRecorder()

		h.HandleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("Expected 302 redirect, got %d", w.Code)
		}
		if w.Header().Get("Location") != "/dashboard" {
			t.Errorf("Expected redirect to /dashboard, got %s", w.Header().Get("Location"))
		}

		cookies := w.Result().Cookies()
		var authCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "kc_at" {
				authCookie = c
				break
			}
		}
		if authCookie == nil {
			t.Fatal("Expected kc_at cookie to be set")
		}
		if authCookie.Value != "mock-access-token-xyz" {
			t.Errorf("Expected cookie value mock-access-token-xyz, got %s", authCookie.Value)
		}
		if !authCookie.HttpOnly || !authCookie.Secure {
			t.Errorf("Expected HttpOnly=true and Secure=true, got HttpOnly=%v Secure=%v", authCookie.HttpOnly, authCookie.Secure)
		}
	})

	t.Run("CallbackWithStateAndPKCE_Success", func(t *testing.T) {
		var receivedVerifier string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			receivedVerifier = r.FormValue("code_verifier")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "token-with-pkce",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		}))
		defer server.Close()

		cfg := keycloak.Config{
			AuthURL:  server.URL,
			Realm:    "test",
			ClientID: "web",
		}
		flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
		h := NewHandler(flow, nil, "/default-dashboard")

		// First, initiate login to get cookie
		loginReq := httptest.NewRequest("GET", "/login?return=/custom/target", nil)
		loginRec := httptest.NewRecorder()
		authURL, err := h.LoginURLWithPKCE(loginRec, loginReq)
		if err != nil {
			t.Fatalf("LoginURLWithPKCE failed: %v", err)
		}

		parsedURL, _ := url.Parse(authURL)
		generatedState := parsedURL.Query().Get("state")
		if generatedState == "" {
			t.Fatal("Expected state query parameter in auth URL")
		}

		// Find the transient cookie
		var txnCookie *http.Cookie
		for _, c := range loginRec.Result().Cookies() {
			if c.Name == h.transientCookieName {
				txnCookie = c
				break
			}
		}
		if txnCookie == nil {
			t.Fatal("Expected transient cookie to be set")
		}

		// Now simulate callback with the state and cookie
		cbReq := httptest.NewRequest("GET", "/callback?code=valid-code&state="+generatedState, nil)
		cbReq.AddCookie(txnCookie)
		cbRec := httptest.NewRecorder()

		h.HandleCallback(cbRec, cbReq)

		if cbRec.Code != http.StatusFound {
			t.Fatalf("Expected 302 Found, got %d, body: %s", cbRec.Code, cbRec.Body.String())
		}
		// Should redirect to the preserved return URL
		if cbRec.Header().Get("Location") != "/custom/target" {
			t.Errorf("Expected redirect to /custom/target, got %s", cbRec.Header().Get("Location"))
		}
		// PKCE verifier should have been sent to token endpoint
		if receivedVerifier == "" {
			t.Error("Expected code_verifier to be sent to token endpoint")
		}

		// Transient cookie should be cleared
		var txnCleared bool
		for _, c := range cbRec.Result().Cookies() {
			if c.Name == h.transientCookieName && c.MaxAge == -1 {
				txnCleared = true
				break
			}
		}
		if !txnCleared {
			t.Error("Expected transient cookie to be cleared after callback")
		}
	})

	t.Run("CallbackWithStateMismatch_Returns400", func(t *testing.T) {
		cfg := keycloak.Config{Realm: "test", ClientID: "web"}
		flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
		h := NewHandler(flow, nil, "/dashboard")

		loginReq := httptest.NewRequest("GET", "/login", nil)
		loginRec := httptest.NewRecorder()
		_, _ = h.LoginURLWithPKCE(loginRec, loginReq)

		var txnCookie *http.Cookie
		for _, c := range loginRec.Result().Cookies() {
			if c.Name == h.transientCookieName {
				txnCookie = c
				break
			}
		}

		// Callback with WRONG state
		cbReq := httptest.NewRequest("GET", "/callback?code=valid-code&state=attacker-state", nil)
		cbReq.AddCookie(txnCookie)
		cbRec := httptest.NewRecorder()

		h.HandleCallback(cbRec, cbReq)

		if cbRec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for state mismatch, got %d", cbRec.Code)
		}
		if !strings.Contains(cbRec.Body.String(), "invalid or missing OAuth state parameter") {
			t.Errorf("Unexpected body: %s", cbRec.Body.String())
		}
	})

	t.Run("CallbackWithCorruptedTransientCookie", func(t *testing.T) {
		cfg := keycloak.Config{Realm: "test", ClientID: "web"}
		flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
		h := NewHandler(flow, nil, "/dashboard")

		cbReq := httptest.NewRequest("GET", "/callback?code=valid-code&state=some-state", nil)
		cbReq.AddCookie(&http.Cookie{Name: h.transientCookieName, Value: "not-valid-base64-json"})
		cbRec := httptest.NewRecorder()

		h.HandleCallback(cbRec, cbReq)

		if cbRec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for corrupted cookie, got %d", cbRec.Code)
		}
	})

	t.Run("CallbackUnsafeReturnURL_FallsBackToDefault", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "token",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		}))
		defer server.Close()

		cfg := keycloak.Config{AuthURL: server.URL, Realm: "test", ClientID: "web"}
		flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
		h := NewHandler(flow, nil, "/default-dashboard")

		// Login with unsafe open redirect return parameter
		loginReq := httptest.NewRequest("GET", "/login?return=//attacker.com/steal", nil)
		loginRec := httptest.NewRecorder()
		authURL, _ := h.LoginURLWithPKCE(loginRec, loginReq)
		parsed, _ := url.Parse(authURL)
		state := parsed.Query().Get("state")

		var txnCookie *http.Cookie
		for _, c := range loginRec.Result().Cookies() {
			if c.Name == h.transientCookieName {
				txnCookie = c
				break
			}
		}

		cbReq := httptest.NewRequest("GET", "/callback?code=valid-code&state="+state, nil)
		cbReq.AddCookie(txnCookie)
		cbRec := httptest.NewRecorder()

		h.HandleCallback(cbRec, cbReq)

		// Unsafe return URL should be ignored, falling back to /default-dashboard
		if cbRec.Header().Get("Location") != "/default-dashboard" {
			t.Errorf("Expected fallback to /default-dashboard, got %s", cbRec.Header().Get("Location"))
		}
	})
}

func TestHandler_HandleLogin(t *testing.T) {
	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}
	flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
	h := NewHandler(flow, nil, "/dashboard", WithTransientCookieName("custom_txn_cookie"))

	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("Expected 302 Found, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("Expected code_challenge in redirect location: %s", loc)
	}
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Errorf("Expected code_challenge_method=S256 in redirect location: %s", loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Errorf("Expected state in redirect location: %s", loc)
	}

	// Check custom transient cookie name
	var txnFound bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "custom_txn_cookie" {
			txnFound = true
			if !c.HttpOnly {
				t.Error("Expected transient cookie to be HttpOnly")
			}
			break
		}
	}
	if !txnFound {
		t.Error("Expected custom_txn_cookie to be set")
	}

	// Test without PKCE
	hNoPKCE := NewHandler(flow, nil, "/dashboard", WithPKCE(false))
	recNoPKCE := httptest.NewRecorder()
	hNoPKCE.HandleLogin(recNoPKCE, req)
	locNoPKCE := recNoPKCE.Header().Get("Location")
	if strings.Contains(locNoPKCE, "code_challenge=") {
		t.Errorf("Did not expect code_challenge when PKCE disabled: %s", locNoPKCE)
	}
}

func Test_extractBearerToken(t *testing.T) {
	t.Run("ValidBearer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer token123")

		token, err := extractBearerToken(req)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if token != "token123" {
			t.Errorf("Expected token123, got %s", token)
		}
	})

	t.Run("BearerSpaceToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer   token123")

		token, err := extractBearerToken(req)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if token != "token123" {
			t.Errorf("Expected token123, got %s", token)
		}
	})

	t.Run("MissingBearer", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "token123")

		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("Expected error for missing Bearer")
		}
	})

	t.Run("EmptyToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer ")

		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("Expected error for empty token")
		}
	})

	t.Run("BasicAuth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("Expected error for Basic auth")
		}
	})

	t.Run("MissingHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		_, err := extractBearerToken(req)
		if err == nil {
			t.Error("Expected error for missing header")
		}
	})
}

func Test_currentURL(t *testing.T) {
	t.Run("WithQuery", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/path?foo=bar", nil)
		u := currentURL(req)
		if u != "/path?foo=bar" {
			t.Errorf("Expected '/path?foo=bar', got '%s'", u)
		}
	})

	t.Run("WithoutQuery", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/path", nil)
		u := currentURL(req)
		if u != "/path" {
			t.Errorf("Expected '/path', got '%s'", u)
		}
	})

	t.Run("Root", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		u := currentURL(req)
		if u != "/" {
			t.Errorf("Expected '/', got '%s'", u)
		}
	})

	t.Run("EmptyURL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.URL.Path = ""
		u := currentURL(req)
		if u != "/" {
			t.Errorf("Expected '/', got '%s'", u)
		}
	})
}

func TestMiddleware_clearAuthCookie(t *testing.T) {
	mockAS := &auth.Service{}

	cfg := keycloak.Config{
		AuthURL:  "http://localhost:8080/auth",
		Realm:    "test",
		ClientID: "web",
	}

	flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at", Path: "/"}, "/login", "http://localhost/callback", nil)
	mw := New(mockAS, cfg, flow)

	cookie := mw.clearAuthCookie()

	if cookie.Name != "kc_at" {
		t.Errorf("Expected cookie name 'kc_at', got '%s'", cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("Expected empty cookie value, got '%s'", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge=-1, got %d", cookie.MaxAge)
	}
	if !cookie.Expires.IsZero() && !cookie.Expires.Before(time.Now()) {
		t.Errorf("Expected expired cookie, got %v", cookie.Expires)
	}
}

// Integration test for full flow
func TestMiddleware_Integration(t *testing.T) {
	jwks := newTestJWKSServer(t)

	cfg := keycloak.Config{
		AuthURL:  jwks.server.URL,
		Realm:    "test",
		ClientID: "web",
	}
	as, err := auth.NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	flow := webflow.New(cfg, webflow.CookieConfig{Name: "kc_at"}, "/login", "http://localhost/callback", nil)
	mw := New(as, cfg, flow)

	r := chi.NewRouter()

	// Public route
	r.Get("/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public"))
	}))

	// Protected route
	r.Group(func(protected chi.Router) {
		protected.Use(mw.Auth())
		protected.Use(mw.RequireRealmRole("admin"))
		protected.Get("/protected", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("protected-admin"))
		}))
	})

	// Test public route
	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for public route, got %d", w.Code)
	}
	if w.Body.String() != "public" {
		t.Errorf("Expected 'public', got '%s'", w.Body.String())
	}

	// Test protected route without cookie -> redirect
	reqUnauth := httptest.NewRequest("GET", "/protected", nil)
	wUnauth := httptest.NewRecorder()
	r.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusFound {
		t.Errorf("Expected 302, got %d", wUnauth.Code)
	}

	// Test protected route with valid cookie and role
	claims := &auth.Claims{
		PreferredUsername: "superadmin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	claims.RealmAccess.Roles = []string{"admin"}
	tok := jwks.signToken(t, claims)

	reqAuth := httptest.NewRequest("GET", "/protected", nil)
	reqAuth.AddCookie(&http.Cookie{Name: "kc_at", Value: tok})
	wAuth := httptest.NewRecorder()
	r.ServeHTTP(wAuth, reqAuth)

	if wAuth.Code != http.StatusOK {
		t.Errorf("Expected 200 for authenticated request, got %d", wAuth.Code)
	}
	if wAuth.Body.String() != "protected-admin" {
		t.Errorf("Expected 'protected-admin', got '%s'", wAuth.Body.String())
	}
}
