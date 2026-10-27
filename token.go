package keycloak

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isklv/slogging"
	"github.com/tidwall/gjson"
)

var (
	errInvalidToken          = errors.New("invalid token")
	errInvalidKeycloakConfig = errors.New("invalid keycloak config")
)

type tokenResponseData struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type tokenRequestData struct {
	// client/server
	requestType string

	// code for client request
	code string

	// credentials for server request
	clientID     string
	clientSecret string
}

func doTokenRequest(reqData *tokenRequestData, cl *Client) (*tokenResponseData, error) {
	data := url.Values{}

	switch reqData.requestType {
	case "client":
		data = url.Values{
			"grant_type":   {"authorization_code"},
			"client_id":    {cl.ClientID},
			"code":         {reqData.code},
			"redirect_uri": {cl.RedirectURL},
		}
	case "server":
		data = url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {reqData.clientID},
			"client_secret": {reqData.clientSecret},
		}
	default:
		return nil, errInvalidRequest
	}

	tokenURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", cl.BaseURL, cl.Realm)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// TODO: rename http.Client
	resp, err := cl.cl.Do(req)
	if err != nil {
		slog.Error("keycloak token request failed",
			slogging.ErrAttr(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errStatusNotOK
	}

	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("keycloak token response reading failed",
			slogging.StringAttr("response", string(bb)))
		return nil, err
	}

	var tokenData tokenResponseData
	err = json.Unmarshal(bb, &tokenData)
	if err != nil {
		return nil, err
	}

	if tokenData.AccessToken == "" {
		return nil, errSomethingWentWrong
	}

	return &tokenData, nil
}

func extractUsername(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	username := gjson.GetBytes(payload, "preferred_username").String()

	return username, nil
}

func extractExpTime(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse payload: %v", err)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("exp claim is missing or invalid")
	}

	return time.Unix(int64(exp), 0), nil
}

func introspectTokenRoles(token, clientID string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	result := gjson.GetBytes(payload, fmt.Sprintf("resource_access.%s.roles", clientID))

	roles := make([]string, 0)
	if result.IsArray() {
		result.ForEach(func(_, value gjson.Result) bool {
			roles = append(roles, value.String())
			return true
		})
	} else {
		return nil, errors.New("roles not found in token")
	}

	return roles, nil
}

func extractPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// DefaultMFAMethods lists standard RFC 8176 and provider authentication methods recognized as MFA.
var DefaultMFAMethods = []string{
	"otp", "mfa", "fido", "fido2", "webauthn", "sms", "hwk", "totp", "hotp", "kba", "push", "duo", "yubikey",
}

// DefaultMFALevels lists standard ACR levels representing MFA.
var DefaultMFALevels = []string{
	"mfa", "gold", "2", "loa-2", "phr",
}

// hasMFAFromPayload checks if decoded JWT payload JSON contains MFA AMR or ACR indicators.
func hasMFAFromPayload(payload []byte) bool {
	amrResult := gjson.GetBytes(payload, "amr")
	if amrResult.Exists() {
		if amrResult.IsArray() {
			for _, item := range amrResult.Array() {
				val := strings.ToLower(strings.TrimSpace(item.String()))
				for _, method := range DefaultMFAMethods {
					if val == method {
						return true
					}
				}
			}
		} else {
			val := strings.ToLower(strings.TrimSpace(amrResult.String()))
			for _, method := range DefaultMFAMethods {
				if val == method {
					return true
				}
			}
		}
	}

	acrResult := gjson.GetBytes(payload, "acr")
	if acrResult.Exists() {
		val := strings.ToLower(strings.TrimSpace(acrResult.String()))
		for _, level := range DefaultMFALevels {
			if val == level {
				return true
			}
		}
	}

	return false
}

// IsTokenMFA parses the token payload and returns true if MFA was verified (via amr or acr).
func IsTokenMFA(token string) (bool, error) {
	payload, err := extractPayload(token)
	if err != nil {
		return false, err
	}
	return hasMFAFromPayload(payload), nil
}

func IsTokenExpired(token string) (bool, error) {
	expTime, err := extractExpTime(token)
	if err != nil {
		return true, err
	}
	if time.Now().After(expTime) {
		return true, nil
	} else {
		return false, nil
	}
}

func (cl *Client) RefreshToken(refreshToken string) (*tokenResponseData, error) {
	if refreshToken == "" {
		return nil, errors.New("empty refresh token")
	}

	form := url.Values{}
	form.Set("client_id", cl.ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cl.BaseURL, cl.Realm),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh token failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenData tokenResponseData
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	return &tokenData, nil
}
