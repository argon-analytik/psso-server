package authentik

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/argon-analytik/psso-server/pkg/constants"
)

// tokenResponse represents a minimal subset of Authentik's token endpoint response.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// VerifyCredentials posts the provided credentials to the Authentik token endpoint
// using the configured client id and secret. It returns nil if the token request
// succeeds, otherwise an error describing the failure.
func VerifyCredentials(username, password string) error {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid")

	req, err := http.NewRequest(http.MethodPost, constants.AuthentikTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(constants.AuthentikClientID, constants.AuthentikClientSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("failed to parse authentik response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if tr.ErrorDescription != "" {
			return fmt.Errorf(tr.ErrorDescription)
		}
		if tr.Error != "" {
			return fmt.Errorf(tr.Error)
		}
		return fmt.Errorf("authentication failed: %s", resp.Status)
	}

	if tr.AccessToken == "" {
		return fmt.Errorf("authentication failed: missing access token")
	}

	return nil
}
