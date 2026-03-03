package chi

import (
	"net/http"

	"github.com/isklv/keycloak/auth"
	"github.com/isklv/keycloak/webflow"
	"github.com/isklv/slogging"
)

type Handler struct {
	flow      *webflow.Flow
	jwt       *auth.Service
	cookie    webflow.CookieConfig
	afterPath string
}

func NewHandler(flow *webflow.Flow, jwtSvc *auth.Service, afterPath string) *Handler {

	return &Handler{
		flow:      flow,
		jwt:       jwtSvc,
		cookie:    flow.CookieConfig(),
		afterPath: afterPath,
	}
}

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	tok, err := h.flow.ExchangeCode(r.Context(), code)
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

	http.Redirect(w, r, h.afterPath, http.StatusFound)
}
