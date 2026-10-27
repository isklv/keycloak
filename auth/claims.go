package auth

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AMRClaim represents the Authentication Methods References claim (RFC 8176).
// It safely decodes from either a standard JSON array of strings (e.g. ["pwd", "otp"])
// or a single string fallback (e.g. "otp").
type AMRClaim []string

// UnmarshalJSON supports unmarshaling both []string and string into AMRClaim.
func (a *AMRClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*a = nil
		return nil
	}

	// 1. Try standard RFC 8176 array of strings: ["pwd", "otp"]
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*a = arr
		return nil
	}

	// 2. Try single string fallback: "otp"
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		if trimmed := strings.TrimSpace(str); trimmed != "" {
			*a = []string{trimmed}
		} else {
			*a = nil
		}
		return nil
	}

	return errors.New("amr claim must be an array of strings or a string")
}

// DefaultMFAMethods lists standard RFC 8176 and provider authentication methods recognized as MFA.
var DefaultMFAMethods = []string{
	"otp", "mfa", "fido", "fido2", "webauthn", "sms", "hwk", "totp", "hotp", "kba", "push", "duo", "yubikey",
}

// DefaultMFALevels lists standard ACR levels representing MFA.
var DefaultMFALevels = []string{
	"mfa", "gold", "2", "loa-2", "phr",
}

type Claims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	AuthorizedParty string   `json:"azp,omitempty"`
	AMR             AMRClaim `json:"amr,omitempty"`
	ACR             string   `json:"acr,omitempty"`

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

// HasAMR returns true if the token's AMR claim contains the specified method (case-insensitive).
func (c *Claims) HasAMR(method string) bool {
	for _, m := range c.AMR {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// HasAnyAMR returns true if the token's AMR claim contains any of the specified methods.
func (c *Claims) HasAnyAMR(methods ...string) bool {
	for _, want := range methods {
		if c.HasAMR(want) {
			return true
		}
	}
	return false
}

// HasACR returns true if the token's ACR claim matches any of the specified levels (case-insensitive).
func (c *Claims) HasACR(levels ...string) bool {
	for _, l := range levels {
		if strings.EqualFold(c.ACR, l) {
			return true
		}
	}
	return false
}

// HasMFA returns true if the token indicates that multi-factor authentication was completed,
// based on standard RFC 8176 AMR methods (e.g. "otp", "mfa", "fido2", "webauthn", "hwk", "sms", "totp")
// or recognized ACR levels (e.g. "mfa", "gold", "2", "loa-2").
func (c *Claims) HasMFA() bool {
	if c.HasAnyAMR(DefaultMFAMethods...) {
		return true
	}
	return c.HasACR(DefaultMFALevels...)
}

