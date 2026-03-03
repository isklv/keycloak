package chi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isklv/keycloak"
	"github.com/isklv/keycloak/auth"
	"github.com/isklv/keycloak/webflow"
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
				http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			slogging.L(r.Context()).Debug("AuthBearer", slogging.StringAttr("response", raw))

			claims, err := m.as.ParseAndValidateToken(r.Context(), raw)
			if err != nil {
				slogging.L(r.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
				http.Error(w, "invalid token", http.StatusUnauthorized)
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
			slogging.L(r.Context()).Debug("RequireAnyRealmRole", slogging.AnyAttr("roles", claims.RealmAccess.Roles))
			if !ok || !claims.HasAnyRealmRole(roles...) {
				http.Error(w, "forbidden", http.StatusForbidden)
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
			if !ok || !claims.HasAnyClientRole(m.cfg.ClientID, roles...) {
				http.Error(w, "forbidden", http.StatusForbidden)
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
	return u.String()
}

func extractBearerToken(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", http.ErrNoCookie // просто готовая ошибка
	}

	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", http.ErrNoCookie
	}

	return parts[1], nil
}
