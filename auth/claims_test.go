package auth

import (
	"encoding/json"
	"testing"
)

func TestAMRClaim_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected AMRClaim
		wantErr  bool
	}{
		{
			name:     "ArrayOfStrings",
			input:    `["pwd", "otp"]`,
			expected: AMRClaim{"pwd", "otp"},
		},
		{
			name:     "SingleString",
			input:    `"otp"`,
			expected: AMRClaim{"otp"},
		},
		{
			name:     "Null",
			input:    `null`,
			expected: nil,
		},
		{
			name:     "EmptyArray",
			input:    `[]`,
			expected: AMRClaim{},
		},
		{
			name:     "EmptyString",
			input:    `""`,
			expected: nil,
		},
		{
			name:    "InvalidNumber",
			input:   `123`,
			wantErr: true,
		},
		{
			name:    "InvalidObject",
			input:   `{"method":"otp"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var amr AMRClaim
			err := json.Unmarshal([]byte(tt.input), &amr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(amr) != len(tt.expected) {
					t.Fatalf("Expected len %d, got %d", len(tt.expected), len(amr))
				}
				for i := range amr {
					if amr[i] != tt.expected[i] {
						t.Errorf("At index %d: expected %q, got %q", i, tt.expected[i], amr[i])
					}
				}
			}
		})
	}
}

func TestClaims_AMRAndMFA(t *testing.T) {
	t.Run("HasAMR_CaseInsensitive", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd", "OTP"},
		}
		if !c.HasAMR("otp") {
			t.Error("Expected HasAMR('otp') to be true")
		}
		if !c.HasAMR("PWD") {
			t.Error("Expected HasAMR('PWD') to be true")
		}
		if c.HasAMR("sms") {
			t.Error("Expected HasAMR('sms') to be false")
		}
	})

	t.Run("HasAnyAMR", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd", "fido2"},
		}
		if !c.HasAnyAMR("otp", "fido2") {
			t.Error("Expected HasAnyAMR('otp', 'fido2') to be true")
		}
		if c.HasAnyAMR("sms", "hwk") {
			t.Error("Expected HasAnyAMR('sms', 'hwk') to be false")
		}
	})

	t.Run("HasACR_CaseInsensitive", func(t *testing.T) {
		c := &Claims{
			ACR: "MFA",
		}
		if !c.HasACR("mfa") {
			t.Error("Expected HasACR('mfa') to be true")
		}
		if !c.HasACR("gold", "mfa") {
			t.Error("Expected HasACR('gold', 'mfa') to be true")
		}
		if c.HasACR("1", "silver") {
			t.Error("Expected HasACR('1', 'silver') to be false")
		}
	})

	t.Run("HasMFA_ViaAMROTP", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd", "otp"},
		}
		if !c.HasMFA() {
			t.Error("Expected HasMFA to be true for OTP")
		}
	})

	t.Run("HasMFA_ViaAMRFIDO2", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"fido2"},
		}
		if !c.HasMFA() {
			t.Error("Expected HasMFA to be true for fido2")
		}
	})

	t.Run("HasMFA_ViaAMRWebAuthn", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd", "webauthn"},
		}
		if !c.HasMFA() {
			t.Error("Expected HasMFA to be true for webauthn")
		}
	})

	t.Run("HasMFA_ViaACR", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd"},
			ACR: "mfa",
		}
		if !c.HasMFA() {
			t.Error("Expected HasMFA to be true for acr=mfa")
		}
	})

	t.Run("HasMFA_ViaACRGold", func(t *testing.T) {
		c := &Claims{
			ACR: "gold",
		}
		if !c.HasMFA() {
			t.Error("Expected HasMFA to be true for acr=gold")
		}
	})

	t.Run("HasMFA_FalseWhenPasswordOnly", func(t *testing.T) {
		c := &Claims{
			AMR: AMRClaim{"pwd"},
			ACR: "1",
		}
		if c.HasMFA() {
			t.Error("Expected HasMFA to be false when only pwd and acr=1")
		}
	})

	t.Run("HasMFA_FalseWhenEmpty", func(t *testing.T) {
		c := &Claims{}
		if c.HasMFA() {
			t.Error("Expected HasMFA to be false when empty")
		}
	})
}
