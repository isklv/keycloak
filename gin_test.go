package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestGinNeedRoleWithMFA(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client := &Client{
		ClientID: "test-client",
	}

	future := time.Now().Add(time.Hour).Unix()

	makeTokenWithRoleAndMFA := func(role string, mfa bool) string {
		claims := map[string]interface{}{
			"exp":                future,
			"preferred_username": "alice",
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
		return makeTestToken(claims)
	}

	setupRouter := func() *gin.Engine {
		r := gin.New()
		r.GET("/protected", client.GinNeedRoleWithMFA("editor"), func(c *gin.Context) {
			username, _ := c.Get("username")
			c.JSON(http.StatusOK, gin.H{"status": "ok", "user": username})
		})
		r.GET("/mfa-only", client.GinNeedMFA(), func(c *gin.Context) {
			username, _ := c.Get("username")
			c.JSON(http.StatusOK, gin.H{"status": "ok", "user": username})
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
		token := makeTokenWithRoleAndMFA("editor", true)
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}

		var res map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		if res["user"] != "alice" {
			t.Errorf("expected user alice, got %s", res["user"])
		}
	})

	t.Run("Valid token with role but WITHOUT MFA", func(t *testing.T) {
		r := setupRouter()
		token := makeTokenWithRoleAndMFA("editor", false)
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
		token := makeTokenWithRoleAndMFA("viewer", true)
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
		token := makeTokenWithRoleAndMFA("any-role", true)
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
		token := makeTokenWithRoleAndMFA("any-role", false)
		req, _ := http.NewRequest(http.MethodGet, "/mfa-only", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})
}
