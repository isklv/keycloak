package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/isklv/keycloak"
	"github.com/isklv/slogging"
	"net/http"
)

const (
	KEYCLOAK_CLIENT_ID       = "clientid"
	KEYCLOAK_REALM           = "realm"
	KEYCLOAK_SERVER_BASE_URL = "https://keycloak"
	KEYCLOAK_REDIRECT_URL    = "http://localhost:8081/auth"
)

func main() {
	options := slogging.NewOptions()
	log := slogging.NewLogger(options)

	client := keycloak.NewClient(keycloak.Config{
		BaseURL:     KEYCLOAK_SERVER_BASE_URL,
		Realm:       KEYCLOAK_REALM,
		ClientID:    KEYCLOAK_CLIENT_ID,
		RedirectURL: KEYCLOAK_REDIRECT_URL,
	})

	router := gin.Default()

	router.GET("/public", ruleGetExampleHandler)

	router.GET("/auth", client.GinAuthHandlerFunc)

	var requiredRoles []string
	requiredRoles = append(requiredRoles, "test-role")

	api := router.Group("/api")
	api.Use(client.GinNeedRole(requiredRoles...))

	api.GET("/protected", protectedHandler)
	api.GET("/info", infoHandler)

	log.Info("Server listening on :8081")
	router.Run(":8081")
}

func ruleGetExampleHandler(c *gin.Context) {
	slogging.L(c.Request.Context()).Info("ruleGetExampleHandler called")
	c.String(http.StatusOK, "Public endpoint accessed")
}

func protectedHandler(c *gin.Context) {
	username, ok := c.Get("username")
	if ok {
		c.String(http.StatusOK, "Hello, %s! You have access to /api/protected", username)
	} else {
		c.String(http.StatusOK, "Hello, anonymous! You reached /api/protected")
	}
}

func infoHandler(c *gin.Context) {
	username, ok := c.Get("username")
	text := fmt.Sprintln("Welcome, ", username)
	if ok {
		c.JSON(http.StatusOK, gin.H{
			"message": text,
			"role":    "k8s",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "Anonymous access",
		})
	}
}
