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
