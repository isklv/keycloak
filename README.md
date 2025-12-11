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
#### Native ####
```
http.HandleFunc("/auth", keycloakClient.AuthHandlerFunc)

enricherRoles := keycloakClient.NeedRole("exampleRole1", "exampleRole2")
http.Handle("/rules", enricherRoles(http.HandlerFunc(sad)))

http.ListenAndServe(":8080", nil)
```
#### Mux ####
```
r := mux.NewRouter()
r.HandleFunc("/auth", keycloakClient.AuthHandlerFunc)

rules := r.Path("/rules").Subrouter()
rules.Handle("/", ruleGetExampleHandler)

rules.Use(keycloakClient.NeedRole("exampleRole1", "exampleRole2"))
```
#### Gin ####
```
r := gin.Default()
r.Handle(http.MethodGet, "/auth", keycloakClient.GinAuthHandlerFunc)

rules := r.Group("/rules")
rules.Handle(http.MethodGet, "/", ruleGetExampleHandler)

rules.Use(keycloakClient.GinNeedRole("exampleRole1", "exampleRole2"))
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
