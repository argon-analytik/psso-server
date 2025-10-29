package authentik

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Client struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func (c *Client) PasswordGrant(ctx context.Context, username, password string) (TokenResponse, error) {
	if c == nil {
		return TokenResponse{}, errors.New("authentik client is nil")
	}
	if c.Endpoint == "" {
		return TokenResponse{}, errors.New("authentik token endpoint not configured")
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid profile email offline_access")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.ClientID != "" {
		req.SetBasicAuth(c.ClientID, c.ClientSecret)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return TokenResponse{}, fmt.Errorf("decode authentik response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if token.ErrorDescription != "" {
			return TokenResponse{}, fmt.Errorf(token.ErrorDescription)
		}
		if token.Error != "" {
			return TokenResponse{}, fmt.Errorf(token.Error)
		}
		return TokenResponse{}, fmt.Errorf("authentik token endpoint returned %s", resp.Status)
	}

	if token.IDToken == "" {
		return TokenResponse{}, fmt.Errorf("authentik token endpoint missing id_token")
	}
	if token.RefreshToken == "" {
		return TokenResponse{}, fmt.Errorf("authentik token endpoint missing refresh_token")
	}

	return token, nil
}
