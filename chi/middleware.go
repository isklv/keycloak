package chi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/tokenutil"
	"github.com/isklv/keycloak/v2/webflow"
	"github.com/isklv/slogging"
)

type Middleware struct {
	flow *webflow.Flow
	as   *auth.Service
	cfg  keycloak.Config
}

func New(as *auth.Service, cfg keycloak.Config, flow *webflow.Flow) *Middleware {
	return &Middleware{
		flow: flow,
		as:   as,
		cfg:  cfg,
	}
}

func (m *Middleware) Auth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(m.flow.CookieName())
			if err != nil || c.Value == "" {
				returnTo := url.PathEscape(currentURL(r))
				http.Redirect(w, r, m.flow.LoginURL()+"?return="+returnTo, http.StatusFound)
				return
			}

			claims, err := m.as.ParseAndValidateToken(r.Context(), c.Value)
			if err != nil {
				slogging.L(r.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
				http.SetCookie(w, m.clearAuthCookie())
				returnTo := url.PathEscape(currentURL(r))
				http.Redirect(w, r, m.flow.LoginURL()+"?return="+returnTo, http.StatusFound)
				return
			}

			ctx := auth.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *Middleware) AuthBearer() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, "missing or invalid Authorization header — expected 'Bearer <token>'", http.StatusUnauthorized)
				return
			}

			slogging.L(r.Context()).Debug("AuthBearer", slogging.StringAttr("token", tokenutil.MaskToken(raw)))

			claims, err := m.as.ParseAndValidateToken(r.Context(), raw)
			if err != nil {
				slogging.L(r.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := auth.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *Middleware) RequireRealmRole(role string) func(next http.Handler) http.Handler {
	return m.RequireAnyRealmRole(role)
}

func (m *Middleware) RequireAnyRealmRole(roles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.FromContext(r.Context())
			if !ok || claims == nil {
				slogging.L(r.Context()).Debug("RequireAnyRealmRole: no claims in context")
				http.Error(w, fmt.Sprintf("forbidden — missing required realm role: %s", strings.Join(roles, ", ")),
					http.StatusForbidden)
				return
			}
			slogging.L(r.Context()).Debug("RequireAnyRealmRole",
				slogging.StringAttr("required", strings.Join(roles, ", ")),
				slogging.StringAttr("have", strings.Join(claims.RealmAccess.Roles, ", ")))
			if !claims.HasAnyRealmRole(roles...) {
				http.Error(w, fmt.Sprintf("forbidden — missing required realm role: %s (have: %s)",
					strings.Join(roles, ", "), strings.Join(claims.RealmAccess.Roles, ", ")),
					http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) RequireClientRole(role string) func(next http.Handler) http.Handler {
	return m.RequireAnyClientRole(role)
}

func (m *Middleware) RequireAnyClientRole(roles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.FromContext(r.Context())
			if !ok || claims == nil {
				http.Error(w, fmt.Sprintf("forbidden — missing required client role: %s", strings.Join(roles, ", ")),
					http.StatusForbidden)
				return
			}

			// Collect actual client roles for the error message
			ra, hasClient := claims.ResourceAccess[m.cfg.ClientID]
			var haveRoles []string
			if hasClient {
				haveRoles = ra.Roles
			}

			if !claims.HasAnyClientRole(m.cfg.ClientID, roles...) {
				http.Error(w, fmt.Sprintf("forbidden — missing required client role [%s]: %s (have: %s)",
					m.cfg.ClientID, strings.Join(roles, ", "), strings.Join(haveRoles, ", ")),
					http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) clearAuthCookie() *http.Cookie {
	cookie := m.flow.CookieConfig()
	return &http.Cookie{
		Name:     cookie.Name,
		Value:    "",
		Path:     cookie.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: cookie.HTTPOnly,
		Secure:   cookie.Secure,
		SameSite: cookie.SameSite,
	}
}

func currentURL(r *http.Request) string {
	u := *r.URL
	u.Scheme = ""
	u.Host = ""
	if u.String() == "" {
		return "/"
	}
	return u.String()
}

func extractBearerToken(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", http.ErrNoCookie // просто готовая ошибка
	}

	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", http.ErrNoCookie
	}

	return strings.TrimSpace(parts[1]), nil
}
