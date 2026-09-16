package chi

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/isklv/keycloak/v2/auth"
	"github.com/isklv/keycloak/v2/tokenutil"
	"github.com/isklv/keycloak/v2/webflow"
	"github.com/isklv/slogging"
)

type Handler struct {
	flow                *webflow.Flow
	jwt                 *auth.Service
	cookie              webflow.CookieConfig
	afterPath           string
	transientCookieName string
	enablePKCE          bool
}

type HandlerOption func(*Handler)

// WithPKCE enables or disables PKCE (RFC 7636) in HandleLogin and HandleCallback.
// Default is true.
func WithPKCE(enable bool) HandlerOption {
	return func(h *Handler) {
		h.enablePKCE = enable
	}
}

// WithTransientCookieName configures the cookie name used to store transient state & PKCE verifier.
// Default is "<auth_cookie_name>_txn" (e.g. "kc_at_txn").
func WithTransientCookieName(name string) HandlerOption {
	return func(h *Handler) {
		if name != "" {
			h.transientCookieName = name
		}
	}
}

func NewHandler(flow *webflow.Flow, jwtSvc *auth.Service, afterPath string, opts ...HandlerOption) *Handler {
	cookieCfg := webflow.CookieConfig{}
	if flow != nil {
		cookieCfg = flow.CookieConfig()
	}

	h := &Handler{
		flow:                flow,
		jwt:                 jwtSvc,
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

func isSafeRedirectURL(u string) bool {
	if u == "" {
		return false
	}
	return strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")
}

// HandleLogin initiates the OAuth2 Authorization Code flow with PKCE (RFC 7636) and state CSRF protection.
// It generates a secure random state and PKCE verifier/challenge, stores them in an HTTPOnly transient cookie,
// and redirects the user to Keycloak's login page. If a 'return' query parameter is present,
// it preserves it so the user can be returned to their intended destination after login.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, err := h.LoginURLWithPKCE(w, r)
	if err != nil {
		slogging.L(r.Context()).Error("failed to initiate login", slogging.ErrAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// LoginURLWithPKCE generates a state and PKCE pair, sets the transient cookie on w,
// and returns the full authorization URL for Keycloak.
func (h *Handler) LoginURLWithPKCE(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := webflow.GenerateState()
	if err != nil {
		return "", err
	}

	var verifier, challenge string
	if h.enablePKCE {
		pkce, err := webflow.GeneratePKCE()
		if err != nil {
			return "", err
		}
		verifier = pkce.Verifier
		challenge = pkce.Challenge
	}

	returnTo := r.URL.Query().Get("return")
	if !isSafeRedirectURL(returnTo) {
		returnTo = ""
	}

	txn := oauthTransient{
		State:        state,
		CodeVerifier: verifier,
		ReturnURL:    returnTo,
	}

	rawTxn, err := encodeTransient(txn)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.transientCookieName,
		Value:    rawTxn,
		Path:     h.cookie.Path,
		Domain:   h.cookie.Domain,
		Secure:   h.cookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	if challenge != "" {
		return h.flow.AuthCodeURLWithPKCE(state, challenge), nil
	}
	return h.flow.AuthCodeURL(state), nil
}

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	var codeVerifier string
	redirectTarget := h.afterPath

	// Validate state & retrieve PKCE verifier from transient cookie if present
	txnCookie, err := r.Cookie(h.transientCookieName)
	if err == nil && txnCookie.Value != "" {
		// Clear transient cookie upon receipt
		http.SetCookie(w, h.clearTransientCookie())

		txn, err := decodeTransient(txnCookie.Value)
		if err != nil {
			slogging.L(r.Context()).Warn("invalid transient cookie", slogging.ErrAttr(err))
			http.Error(w, "invalid or corrupt OAuth state", http.StatusBadRequest)
			return
		}

		state := q.Get("state")
		if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(txn.State)) != 1 {
			slogging.L(r.Context()).Warn("state mismatch in callback",
				slogging.StringAttr("query_state", state),
				slogging.StringAttr("cookie_state", txn.State),
			)
			http.Error(w, "invalid or missing OAuth state parameter", http.StatusBadRequest)
			return
		}

		codeVerifier = txn.CodeVerifier
		if isSafeRedirectURL(txn.ReturnURL) {
			redirectTarget = txn.ReturnURL
		}
	}

	var tok *tokenutil.CommonToken
	if codeVerifier != "" {
		tok, err = h.flow.ExchangeCodeWithPKCE(r.Context(), code, codeVerifier)
	} else {
		tok, err = h.flow.ExchangeCode(r.Context(), code)
	}

	if err != nil {
		slogging.L(r.Context()).Error("token exchange failed", slogging.ErrAttr(err))
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
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
	http.SetCookie(w, cookie)

	http.Redirect(w, r, redirectTarget, http.StatusFound)
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
