package gin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/tokenutil"
	"github.com/isklv/keycloak/v2/webflow"
	"github.com/isklv/slogging"
)

// ErrInvalidBearerHeader is returned when the Authorization header is missing or not a valid Bearer token.
var ErrInvalidBearerHeader = errors.New("missing or invalid authorization header")

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

func (m *Middleware) extractToken(c *gin.Context) (string, bool) {
	// 1. Check cookies (configured cookie name, fallback to "access_token" or "kc_at")
	cookieNames := []string{"kc_at", "access_token"}
	if m.flow != nil && m.flow.CookieName() != "" {
		cookieNames = append([]string{m.flow.CookieName()}, cookieNames...)
	}
	for _, name := range cookieNames {
		if cookie, err := c.Cookie(name); err == nil && cookie != "" {
			return cookie, true
		}
	}

	// 2. Check Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1]), true
		}
	}

	return "", false
}

// Auth authenticates requests via cookie or bearer token.
func (m *Middleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, have := m.extractToken(c)
		if !have {
			m.handleUnauthorized(c)
			return
		}

		claims, err := m.as.ParseAndValidateToken(c.Request.Context(), tokenStr)
		if err != nil {
			slogging.L(c.Request.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
			m.clearAuthCookie(c)
			m.handleUnauthorized(c)
			return
		}

		ctx := auth.WithClaims(c.Request.Context(), claims)
		ctx = context.WithValue(ctx, "username", claims.PreferredUsername)
		c.Request = c.Request.WithContext(ctx)
		c.Set("claims", claims)
		c.Set("username", claims.PreferredUsername)
		c.Next()
	}
}

// AuthCookie authenticates requests using cookies and returns 401 on failure.
func (m *Middleware) AuthCookie() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, have := m.extractToken(c)
		if !have {
			m.writeUnauthorizedJSON(c)
			return
		}

		claims, err := m.as.ParseAndValidateToken(c.Request.Context(), tokenStr)
		if err != nil {
			slogging.L(c.Request.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
			m.clearAuthCookie(c)
			m.writeUnauthorizedJSON(c)
			return
		}

		ctx := auth.WithClaims(c.Request.Context(), claims)
		ctx = context.WithValue(ctx, "username", claims.PreferredUsername)
		c.Request = c.Request.WithContext(ctx)
		c.Set("claims", claims)
		c.Set("username", claims.PreferredUsername)
		c.Next()
	}
}

// AuthBearer authenticates requests using the Authorization: Bearer <token> header.
func (m *Middleware) AuthBearer() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if authz == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			return
		}
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "expected 'Bearer <token>'"})
			return
		}

		raw := strings.TrimSpace(parts[1])
		slogging.L(c.Request.Context()).Debug("AuthBearer", slogging.StringAttr("token", tokenutil.MaskToken(raw)))

		claims, err := m.as.ParseAndValidateToken(c.Request.Context(), raw)
		if err != nil {
			slogging.L(c.Request.Context()).Error("ParseAndValidateToken", slogging.ErrAttr(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "details": err.Error()})
			return
		}

		ctx := auth.WithClaims(c.Request.Context(), claims)
		ctx = context.WithValue(ctx, "username", claims.PreferredUsername)
		c.Request = c.Request.WithContext(ctx)
		c.Set("claims", claims)
		c.Set("username", claims.PreferredUsername)
		c.Next()
	}
}

func (m *Middleware) RequireRealmRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := m.resolveClaims(c)
		if !ok || claims == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !claims.HasAnyRealmRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":          "forbidden",
				"required_roles": roles,
				"have_roles":     claims.RealmAccess.Roles,
			})
			return
		}
		c.Next()
	}
}

func (m *Middleware) RequireClientRole(client string, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := m.resolveClaims(c)
		if !ok || claims == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !claims.HasAnyClientRole(client, roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":          "forbidden",
				"client":         client,
				"required_roles": roles,
			})
			return
		}
		c.Next()
	}
}

// RequireMFA ensures the authenticated caller completed multi-factor authentication (MFA).
func (m *Middleware) RequireMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := m.resolveClaims(c)
		if !ok || claims == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		if !claims.HasMFA() {
			slogging.L(c.Request.Context()).Warn("user does not have MFA",
				slogging.StringAttr("username", claims.PreferredUsername),
				slogging.AnyAttr("amr", claims.AMR),
				slogging.StringAttr("acr", claims.ACR),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "mfa_required",
				"message": "multi-factor authentication (MFA) required",
			})
			return
		}
		c.Next()
	}
}

// RequireRealmRoleWithMFA requires at least one of the specified realm roles AND multi-factor authentication.
func (m *Middleware) RequireRealmRoleWithMFA(roles ...string) gin.HandlerFunc {
	roleMW := m.RequireRealmRole(roles...)
	mfaMW := m.RequireMFA()
	return func(c *gin.Context) {
		roleMW(c)
		if c.IsAborted() {
			return
		}
		mfaMW(c)
	}
}

// RequireClientRoleWithMFA requires at least one of the specified client roles AND multi-factor authentication.
func (m *Middleware) RequireClientRoleWithMFA(client string, roles ...string) gin.HandlerFunc {
	roleMW := m.RequireClientRole(client, roles...)
	mfaMW := m.RequireMFA()
	return func(c *gin.Context) {
		roleMW(c)
		if c.IsAborted() {
			return
		}
		mfaMW(c)
	}
}

// GinNeedRole validates authentication and checks if the user has any of the specified roles
// (checking realm roles and client roles for cfg.ClientID).
func (m *Middleware) GinNeedRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, have := m.extractToken(c)
		if !have {
			slogging.L(c.Request.Context()).Warn("user has no access token in cookie or header",
				slogging.StringAttr("url", c.Request.URL.String()))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, err := m.as.ParseAndValidateToken(c.Request.Context(), tokenStr)
		if err != nil {
			slogging.L(c.Request.Context()).Warn("failed to validate token", slogging.ErrAttr(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if len(requiredRoles) > 0 {
			hasRole := claims.HasAnyRealmRole(requiredRoles...)
			if !hasRole && m.cfg.ClientID != "" {
				hasRole = claims.HasAnyClientRole(m.cfg.ClientID, requiredRoles...)
			}
			if !hasRole {
				slogging.L(c.Request.Context()).Warn("user does not have required role",
					slogging.AnyAttr("required_roles", requiredRoles),
					slogging.StringAttr("username", claims.PreferredUsername),
				)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		ctx := auth.WithClaims(c.Request.Context(), claims)
		ctx = context.WithValue(ctx, "username", claims.PreferredUsername)
		c.Request = c.Request.WithContext(ctx)
		c.Set("claims", claims)
		c.Set("username", claims.PreferredUsername)
		c.Next()
	}
}

// GinNeedRoleWithMFA requires authentication, role membership, AND multi-factor authentication (MFA).
func (m *Middleware) GinNeedRoleWithMFA(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, have := m.extractToken(c)
		if !have {
			slogging.L(c.Request.Context()).Warn("user has no access token in cookie or header",
				slogging.StringAttr("url", c.Request.URL.String()))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, err := m.as.ParseAndValidateToken(c.Request.Context(), tokenStr)
		if err != nil {
			slogging.L(c.Request.Context()).Warn("failed to validate token", slogging.ErrAttr(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if len(requiredRoles) > 0 {
			hasRole := claims.HasAnyRealmRole(requiredRoles...)
			if !hasRole && m.cfg.ClientID != "" {
				hasRole = claims.HasAnyClientRole(m.cfg.ClientID, requiredRoles...)
			}
			if !hasRole {
				slogging.L(c.Request.Context()).Warn("user does not have required role",
					slogging.AnyAttr("required_roles", requiredRoles),
					slogging.StringAttr("username", claims.PreferredUsername),
				)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		if !claims.HasMFA() {
			slogging.L(c.Request.Context()).Warn("user does not have MFA",
				slogging.StringAttr("username", claims.PreferredUsername),
				slogging.AnyAttr("amr", claims.AMR),
				slogging.StringAttr("acr", claims.ACR),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "mfa_required",
				"message": "multi-factor authentication (MFA) required",
			})
			return
		}

		ctx := auth.WithClaims(c.Request.Context(), claims)
		ctx = context.WithValue(ctx, "username", claims.PreferredUsername)
		c.Request = c.Request.WithContext(ctx)
		c.Set("claims", claims)
		c.Set("username", claims.PreferredUsername)
		c.Next()
	}
}

// GinNeedMFA requires the caller to have MFA without specific role restriction.
func (m *Middleware) GinNeedMFA() gin.HandlerFunc {
	return m.GinNeedRoleWithMFA()
}

func (m *Middleware) resolveClaims(c *gin.Context) (*auth.Claims, bool) {
	if val, exists := c.Get("claims"); exists {
		if claims, ok := val.(*auth.Claims); ok {
			return claims, true
		}
	}
	return auth.FromContext(c.Request.Context())
}

func (m *Middleware) handleUnauthorized(c *gin.Context) {
	if isAJAX(c.Request) {
		m.writeUnauthorizedJSON(c)
		return
	}
	if m.flow == nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	returnTo := url.PathEscape(c.Request.URL.String())
	c.Redirect(http.StatusFound, m.flow.LoginURL()+"?return="+returnTo)
	c.Abort()
}

func (m *Middleware) writeUnauthorizedJSON(c *gin.Context) {
	loginURL := ""
	if m.flow != nil {
		loginURL = m.flow.LoginURL() + "?return=" + url.PathEscape(c.Request.URL.String())
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":     "unauthorized",
		"login_url": loginURL,
	})
}

func (m *Middleware) clearAuthCookie(c *gin.Context) {
	if m.flow == nil {
		return
	}
	cookieCfg := m.flow.CookieConfig()
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cookieCfg.Name,
		Value:    "",
		Path:     cookieCfg.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: cookieCfg.HTTPOnly,
		Secure:   cookieCfg.Secure,
		SameSite: cookieCfg.SameSite,
	})
}

func isAJAX(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}
	return false
}
