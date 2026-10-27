package gin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/auth"
)

func makeTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + payload + "." + sig
}

func TestGinMiddlewareMFA(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := keycloak.Config{
		AuthURL:  "https://auth.example.com",
		Realm:    "test-realm",
		ClientID: "test-client",
	}

	authSvc := auth.NewServiceWithKeyfunc(cfg, nil)
	mw := New(authSvc, cfg, nil)

	makeToken := func(role string, mfa bool) string {
		claims := map[string]interface{}{
			"exp":                time.Now().Add(time.Hour).Unix(),
			"preferred_username": "bob",
			"resource_access": map[string]interface{}{
				"test-client": map[string]interface{}{
					"roles": []string{role},
				},
			},
		}
		if mfa {
			claims["amr"] = []string{"pwd", "otp"}
		} else {
			claims["amr"] = []string{"pwd"}
		}
		return makeTestJWT(claims)
	}

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.GET("/protected", mw.GinNeedRoleWithMFA("editor"), func(c *gin.Context) {
			user, _ := c.Get("username")
			c.JSON(http.StatusOK, gin.H{"status": "ok", "user": user})
		})
		r.GET("/mfa-only", mw.GinNeedMFA(), func(c *gin.Context) {
			user, _ := c.Get("username")
			c.JSON(http.StatusOK, gin.H{"status": "ok", "user": user})
		})
		return r
	}

	t.Run("No token provided", func(t *testing.T) {
		r := setupRouter()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("Valid token with role and MFA", func(t *testing.T) {
		r := setupRouter()
		token := makeToken("editor", true)
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("Valid token with role but WITHOUT MFA", func(t *testing.T) {
		r := setupRouter()
		token := makeToken("editor", false)
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}

		var res map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		if res["error"] != "mfa_required" {
			t.Errorf("expected error mfa_required, got %s", res["error"])
		}
	})

	t.Run("Valid token with MFA but WRONG role", func(t *testing.T) {
		r := setupRouter()
		token := makeToken("viewer", true)
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("MFA-only endpoint with MFA", func(t *testing.T) {
		r := setupRouter()
		token := makeToken("viewer", true)
		req, _ := http.NewRequest(http.MethodGet, "/mfa-only", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", w.Code)
		}
	})

	t.Run("MFA-only endpoint without MFA", func(t *testing.T) {
		r := setupRouter()
		token := makeToken("viewer", false)
		req, _ := http.NewRequest(http.MethodGet, "/mfa-only", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})
}
