package keycloak

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeTestToken(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return header + "." + payload + "." + sig
}

func TestIsTokenMFA(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name      string
		claims    map[string]interface{}
		expectMFA bool
	}{
		{
			name: "MFA with amr array containing otp",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"amr":                []string{"pwd", "otp"},
			},
			expectMFA: true,
		},
		{
			name: "MFA with amr array containing webauthn",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"amr":                []string{"pwd", "webauthn"},
			},
			expectMFA: true,
		},
		{
			name: "MFA with amr string",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"amr":                "totp",
			},
			expectMFA: true,
		},
		{
			name: "MFA with acr mfa",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"acr":                "mfa",
			},
			expectMFA: true,
		},
		{
			name: "MFA with acr loa-2",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"acr":                "loa-2",
			},
			expectMFA: true,
		},
		{
			name: "No MFA with password only",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
				"amr":                []string{"pwd"},
				"acr":                "1",
			},
			expectMFA: false,
		},
		{
			name: "No MFA without amr or acr",
			claims: map[string]interface{}{
				"exp":                future,
				"preferred_username": "john_doe",
			},
			expectMFA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := makeTestToken(tt.claims)
			hasMFA, err := IsTokenMFA(token)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hasMFA != tt.expectMFA {
				t.Errorf("expected MFA %v, got %v", tt.expectMFA, hasMFA)
			}
		})
	}
}

func TestIsTokenMFA_InvalidToken(t *testing.T) {
	_, err := IsTokenMFA("invalid-token")
	if err == nil {
		t.Errorf("expected error for invalid token, got nil")
	}
}
