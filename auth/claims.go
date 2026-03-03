package auth

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	AuthorizedParty string `json:"azp,omitempty"`

	jwt.RegisteredClaims
}

func (c *Claims) HasRealmRole(role string) bool {
	for _, r := range c.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (c *Claims) HasAnyRealmRole(roles ...string) bool {
	for _, want := range roles {
		if c.HasRealmRole(want) {
			return true
		}
	}
	return false
}

func (c *Claims) HasClientRole(client, role string) bool {
	ra, ok := c.ResourceAccess[client]
	if !ok {
		return false
	}
	for _, r := range ra.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (c *Claims) HasAnyClientRole(clientID string, roles ...string) bool {
	for _, r := range roles {
		if c.HasClientRole(clientID, r) {
			return true
		}
	}
	return false
}
