package gin

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/tokenutil"
	"github.com/isklv/keycloak/v2/webflow"
	"github.com/isklv/slogging"
)

type Handler struct {
	flow                 *webflow.Flow
	cookie               webflow.CookieConfig
	afterPath            string
	transientCookieName  string
	enablePKCE           bool
	allowedRedirectHosts []string
	allowAnyRedirectURL  bool
	redirectValidator    func(string) bool
}

type HandlerOption func(*Handler)

func WithPKCE(enable bool) HandlerOption {
	return func(h *Handler) {
		h.enablePKCE = enable
	}
}

func WithTransientCookieName(name string) HandlerOption {
	return func(h *Handler) {
		if name != "" {
			h.transientCookieName = name
		}
	}
}

func WithAllowedRedirectHosts(hosts ...string) HandlerOption {
	return func(h *Handler) {
		h.allowedRedirectHosts = append(h.allowedRedirectHosts, hosts...)
	}
}

func WithAllowAnyRedirect(allow bool) HandlerOption {
	return func(h *Handler) {
		h.allowAnyRedirectURL = allow
	}
}

func WithRedirectValidator(fn func(string) bool) HandlerOption {
	return func(h *Handler) {
		h.redirectValidator = fn
	}
}

func NewHandler(flow *webflow.Flow, _ *auth.Service, afterPath string, opts ...HandlerOption) *Handler {
	if afterPath == "" {
		afterPath = "/"
	}
	cookieCfg := webflow.CookieConfig{}
	if flow != nil {
		cookieCfg = flow.CookieConfig()
	}

	h := &Handler{
		flow:                flow,
		cookie:              cookieCfg,
		afterPath:           afterPath,
		transientCookieName: cookieCfg.Name + "_txn",
		enablePKCE:          true,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

type oauthTransient struct {
	State        string `json:"s"`
	CodeVerifier string `json:"v,omitempty"`
	ReturnURL    string `json:"r,omitempty"`
}

func encodeTransient(txn oauthTransient) (string, error) {
	data, err := json.Marshal(txn)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeTransient(raw string) (*oauthTransient, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var txn oauthTransient
	if err := json.Unmarshal(data, &txn); err != nil {
		return nil, err
	}
	return &txn, nil
}

func (h *Handler) isSafeRedirect(u string) bool {
	if u == "" {
		return false
	}
	if strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//") {
		return true
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	if h.allowAnyRedirectURL {
		return true
	}
	if h.redirectValidator != nil {
		return h.redirectValidator(u)
	}
	targetHost := parsed.Host
	for _, pattern := range h.allowedRedirectHosts {
		if matchHost(pattern, targetHost) {
			return true
		}
	}
	if afterPathParsed, err := url.Parse(h.afterPath); err == nil && afterPathParsed.Host != "" {
		if matchHost(afterPathParsed.Host, targetHost) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}

	hostName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		if !strings.Contains(pattern, ":") {
			hostName = h
		}
	}

	if pattern == host || pattern == hostName {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(hostName, suffix) || hostName == pattern[2:]
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(hostName, pattern) || hostName == pattern[1:]
	}

	return false
}

// HandleAuth handles unified login/callback flow (compatible with GinAuthHandlerFunc).
func (h *Handler) HandleAuth(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		h.HandleLogin(c)
		return
	}
	h.HandleCallback(c)
}

func (h *Handler) HandleLogin(c *gin.Context) {
	state, err := webflow.GenerateState()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	var verifier, challenge string
	if h.enablePKCE {
		pkce, err := webflow.GeneratePKCE()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		verifier = pkce.Verifier
		challenge = pkce.Challenge
	}

	returnTo := c.Query("return")
	if !h.isSafeRedirect(returnTo) {
		returnTo = ""
	}

	txn := oauthTransient{
		State:        state,
		CodeVerifier: verifier,
		ReturnURL:    returnTo,
	}

	rawTxn, err := encodeTransient(txn)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.transientCookieName,
		Value:    rawTxn,
		Path:     h.cookie.Path,
		Domain:   h.cookie.Domain,
		Secure:   h.cookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	var authURL string
	if challenge != "" {
		authURL = h.flow.AuthCodeURLWithPKCE(state, challenge)
	} else {
		authURL = h.flow.AuthCodeURL(state)
	}

	c.Redirect(http.StatusFound, authURL)
}

func (h *Handler) HandleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing code parameter"})
		return
	}

	var codeVerifier string
	redirectTarget := h.afterPath
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	txnCookie, err := c.Cookie(h.transientCookieName)
	if err == nil && txnCookie != "" {
		http.SetCookie(c.Writer, h.clearTransientCookie())

		txn, err := decodeTransient(txnCookie)
		if err == nil {
			state := c.Query("state")
			if state != "" && subtle.ConstantTimeCompare([]byte(state), []byte(txn.State)) == 1 {
				codeVerifier = txn.CodeVerifier
				if h.isSafeRedirect(txn.ReturnURL) {
					redirectTarget = txn.ReturnURL
				}
			}
		}
	}

	var tok *tokenutil.CommonToken
	if codeVerifier != "" {
		tok, err = h.flow.ExchangeCodeWithPKCE(c.Request.Context(), code, codeVerifier)
	} else {
		tok, err = h.flow.ExchangeCode(c.Request.Context(), code)
	}

	if err != nil {
		slogging.L(c.Request.Context()).Error("token exchange failed", slogging.ErrAttr(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "token exchange failed"})
		return
	}

	cookie := &http.Cookie{
		Name:     h.cookie.Name,
		Value:    tok.AccessToken,
		Path:     h.cookie.Path,
		Domain:   h.cookie.Domain,
		Secure:   h.cookie.Secure,
		HttpOnly: h.cookie.HTTPOnly,
		SameSite: h.cookie.SameSite,
		Expires:  tok.ExpiresAt,
	}
	http.SetCookie(c.Writer, cookie)

	// Also set access_token cookie for legacy compatibility
	if h.cookie.Name != "access_token" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "access_token",
			Value:    tok.AccessToken,
			Path:     h.cookie.Path,
			Domain:   h.cookie.Domain,
			Secure:   h.cookie.Secure,
			HttpOnly: h.cookie.HTTPOnly,
			SameSite: h.cookie.SameSite,
			Expires:  tok.ExpiresAt,
		})
	}

	c.Redirect(http.StatusFound, redirectTarget)
}

func (h *Handler) clearTransientCookie() *http.Cookie {
	return &http.Cookie{
		Name:     h.transientCookieName,
		Value:    "",
		Path:     h.cookie.Path,
		Domain:   h.cookie.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookie.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}
