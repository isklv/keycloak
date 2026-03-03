package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/isklv/slogging"

	"github.com/go-chi/chi/v5"

	"github.com/isklv/keycloak"
	"github.com/isklv/keycloak/auth"
	chiweb "github.com/isklv/keycloak/chi"
	"github.com/isklv/keycloak/clientcred"
	"github.com/isklv/keycloak/webflow"
)

func main() {
	options := slogging.NewOptions()
	options.SetLevel(slogging.LevelDebug.String())
	log := slogging.NewLogger(options)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authURL := os.Getenv("KEYCLOAK_AUTH_URL")
	authBackendURL := os.Getenv("KEYCLOAK_BACKEND_AUTH_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	baseURL := os.Getenv("APP_BASE_URL")
	listenAddr := os.Getenv("APP_LISTEN_ADDR")

	// init api2api
	cfgApi2Api := keycloak.Config{
		Realm:          "test",
		AuthURL:        authBackendURL,
		BackendAuthURL: authBackendURL,
		ClientID:       "svc",
		ClientSecret:   "RZLHtv1Y6O3ekgewA9EHl9ppqovRo5nY",
	}

	asApi2Api, err := auth.NewService(
		ctx,
		cfgApi2Api,
	)
	if err != nil {
		log.Error("Auth service error", slogging.ErrAttr(err))
		os.Exit(1)
	}
	mwApi2Api := chiweb.New(asApi2Api, cfgApi2Api, nil)

	// init webauth
	cfg := keycloak.Config{
		AuthURL:        authURL,
		BackendAuthURL: authBackendURL,
		Realm:          realm,
		ClientID:       clientID,
	}

	flow := webflow.New(
		cfg,
		webflow.CookieConfig{
			Name:     "kc_at",
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
		"/login",
		baseURL+"/callback",
		nil,
	)

	as, err := auth.NewService(
		ctx,
		cfg,
	)
	if err != nil {
		log.Error("Auth service error", slogging.ErrAttr(err))
		os.Exit(1)
	}

	chiHandler := chiweb.NewHandler(
		flow,
		as,
		"/",
	)

	mw := chiweb.New(as, cfg, flow)

	r := chi.NewRouter()

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		state := "random-state"
		http.Redirect(w, r, flow.AuthCodeURL(state), http.StatusFound)
	})

	r.Get("/callback", chiHandler.HandleCallback)

	r.Get("/api2api", func(w http.ResponseWriter, r *http.Request) {

		ts := clientcred.NewTokenSource(cfgApi2Api, nil)

		httpClient := &http.Client{
			Transport: clientcred.RoundTripper{
				Base: http.DefaultTransport,
				TS:   ts,
			},
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, baseURL+"/api/v1/data", nil)
		if err != nil {
			log.Error("Request error", slogging.ErrAttr(err))
			http.Error(w, "Request error", http.StatusBadRequest)
			return
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Error("Request error", slogging.ErrAttr(err))
			http.Error(w, "Request error", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)

	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(mwApi2Api.AuthBearer())

		r.With(mwApi2Api.RequireAnyRealmRole("api_v1")).Get("/data", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())

			log.Info(
				"Hello",
				slogging.StringAttr("username", claims.PreferredUsername),
				slogging.AnyAttr("roles", claims.RealmAccess),
			)

			if claims.AuthorizedParty != "svc" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok": true}`))
		})
	})

	r.Group(func(protected chi.Router) {
		protected.Use(mw.Auth())

		protected.With(mw.RequireAnyClientRole("read", "write")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			log.Info(
				"Hello",
				slogging.StringAttr("username", claims.PreferredUsername),
				slogging.AnyAttr("roles", claims.ResourceAccess),
			)
		})
	})

	log.Info("listening", slogging.StringAttr("port", listenAddr))
	if err := http.ListenAndServe(listenAddr, r); err != nil {
		log.Error("Server error", slogging.ErrAttr(err))
	}
}
