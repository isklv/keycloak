# Getting #
```
go get -u github.com/isklv/keycloak
```

# Usage #
## Initialize ##

### Client ###
This is example values. The keycloak should be initialized where it will be used or passed as a function parameter. 
```
keycloakClient := keycloak.NewClient(keycloak.Config{
		BaseURL:     "https://keycloak/",
		ClientID:    "web-ecom",
		Realm:       "office",
		RedirectURL: "https://localhost/auth",
	})
```

### Server ###
```
keycloakServer := keycloak.NewClient(keycloak.Config{
        BaseURL:  cfg.KeycloakBaseURL,
        ClientID: cfg.KeycloakInternalAuthUsername,
        Realm:    cfg.KeycloakRealm,
    })
```
## Authorization ##
### Client ###
#### Chi ####
```
// cmd/server/main.go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"

    authChi "github.com/isklv/keycloak/auth"
	chiMW "github.com/isklv/keycloak/chi"
)

func main() {
    <!-- cfg := auth.Config{

    } -->

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    cfg := keycloak.Config{ /* ... */ }

	validator, _ := jwt.NewValidator(ctx, cfg)

	authChi := chiMW.New(chiMW.Config{
		Validator: validator,
	})

	r := chi.NewRouter()
	r.Use(authChi.Auth())
	r.Route("/admin", func(r chi.Router) {
		r.Use(authChi.RequireRealmRole("admin"))
		r.Get("/", handler)
	})

    log.Println("listening on :8080")
    if err := http.ListenAndServe(":8080", r); err != nil {
        log.Fatal(err)
    }
}
```

### Server ###
```
package main

import (
	"fmt"

	"github.com/isklv/keycloak"
	"github.com/isklv/keycloak/persistent"
)

type Service struct {
	session *persistent.Session
}

func main() {
	cl, err := persistent.NewClient("https://keycloak", "internalApi")
	if err != nil {
		return
	}

	session := cl.NewSession(keycloak.Credentials{
		ClientID:     "clientId",
		ClientSecret: "examplesecret",
	})

	svc := Service{
		session: session,
	}

	accessToken, err := svc.session.GetAccessToken()
	if err != nil {
		return
	}

	fmt.Println(accessToken)
}

```

### TokenClient ###
It should be used if you only need token authentication from another server (not global keycloak from environment variables).
For example, for systems like api2api.  
```
r := mux.NewRouter()
r.HandleFunc("/auth", keycloakClient.AuthHandlerFunc)

tc := &keycloak.TokenClient{}

api := r.PathPrefix("/api").Subrouter()
api.Use(tc.NeedTokenRole("exampleRole1", "exampleRole1"))
api.HandleFunc("/", getExampleHandler)
```

## Test Keycloak ###
1. Create realm `test`
2. Create Client with name `web`
3. Set Valid redirect URIs `http://localhost:3000/callback` in Client name `web`
4. Create user and set password in Credentials tab
5. Create in client `web` `client role` `read` and `write` and `test`
6. Add to user from step 3 `client role` `read` and `test`
7. Try to login

## Test Keycloak api2api ###
1. Create Client with name `svc`
2. Set Client authentication=on and Service account roles=on in Capavility config and click Save
3. Select tab `Credentials` and copy Client Secret
4. Set to client secret in main.go to config api2api
5. Create in Realm roles `api_v1`
5. Add to client `svc` in tab `Service account roles` realm role `api_v1`
6. Test it
