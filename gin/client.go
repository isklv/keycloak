package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/isklv/keycloak/v2"
	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/webflow"
)

// Client provides unified Keycloak authentication, authorization, and Gin middlewares in v2.
type Client struct {
	BaseURL     string
	ClientID    string
	Realm       string
	RedirectURL string
	Config      keycloak.Config

	Flow       *webflow.Flow
	AuthSvc    *auth.Service
	Middleware *Middleware
	Handler    *Handler
}

// NewClient initializes a Keycloak v2 Gin Client with webflow and Gin adapters.
func NewClient(cfg keycloak.Config) Client {
	if cfg.AuthURL == "" && cfg.BaseURL != "" {
		cfg.AuthURL = cfg.BaseURL
	}
	if cfg.BaseURL == "" && cfg.AuthURL != "" {
		cfg.BaseURL = cfg.AuthURL
	}

	flow := webflow.New(cfg, webflow.CookieConfig{
		Name: "access_token",
	}, "", cfg.RedirectURL, http.DefaultClient)

	// Auth service initialized with nil jwks allows non-blocking startup and offline verification
	authSvc := auth.NewServiceWithKeyfunc(cfg, nil)

	mw := New(authSvc, cfg, flow)
	h := NewHandler(flow, authSvc, "/")

	return Client{
		BaseURL:     cfg.BaseURL,
		ClientID:    cfg.ClientID,
		Realm:       cfg.Realm,
		RedirectURL: cfg.RedirectURL,
		Config:      cfg,
		Flow:        flow,
		AuthSvc:     authSvc,
		Middleware:  mw,
		Handler:     h,
	}
}

// GinAuthHandlerFunc handles OAuth login and callback redirection.
func (cl Client) GinAuthHandlerFunc(c *gin.Context) {
	cl.Handler.HandleAuth(c)
}

// GinNeedRole returns a Gin middleware requiring at least one of the specified roles.
func (cl Client) GinNeedRole(requiredRoles ...string) gin.HandlerFunc {
	return cl.Middleware.GinNeedRole(requiredRoles...)
}

// GinNeedRoleWithMFA returns a Gin middleware requiring at least one of the specified roles AND MFA.
func (cl Client) GinNeedRoleWithMFA(requiredRoles ...string) gin.HandlerFunc {
	return cl.Middleware.GinNeedRoleWithMFA(requiredRoles...)
}

// GinNeedMFA returns a Gin middleware requiring Multi-Factor Authentication.
func (cl Client) GinNeedMFA() gin.HandlerFunc {
	return cl.Middleware.GinNeedMFA()
}
