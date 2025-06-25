package authentik

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/twocanoes/psso-server/pkg/constants"
)

// VerifyAndFetchRoles contacts the Authentik token endpoint using the Password
// grant. It returns the roles derived from the user's groups.
func VerifyAndFetchRoles(username, password string) ([]string, error) {
	if constants.AuthentikTokenEndpoint == "" ||
		constants.AuthentikClientID == "" ||
		constants.AuthentikClientSecret == "" {
		return nil, errors.New("authentik credentials not configured")
	}

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", constants.AuthentikClientID)
	data.Set("client_secret", constants.AuthentikClientSecret)
	data.Set("scope", "openid profile email")

	resp, err := http.PostForm(constants.AuthentikTokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.IDToken == "" {
		return nil, errors.New("id_token missing")
	}

	groups, err := groupsFromIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, err
	}

	roles := groupsToRoles(groups)
	return roles, nil
}

func groupsFromIDToken(idToken string) ([]string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims.Groups, nil
}

func groupsToRoles(groups []string) []string {
	rolesSet := map[string]struct{}{}
	adminGroups := strings.Split(constants.AdminGroups, ",")

	for _, g := range groups {
		clean := strings.TrimSpace(g)
		lower := strings.ToLower(clean)
		switch lower {
		case "net-admin", "net_admins", "netadmins":
			rolesSet["net-admin"] = struct{}{}
		case "software-install", "software_install":
			rolesSet["software-install"] = struct{}{}
		case "psso-standard-users", "psso_standard_users":
			rolesSet["psso-standard-users"] = struct{}{}
		}
		for _, ag := range adminGroups {
			if strings.EqualFold(clean, strings.TrimSpace(ag)) {
				rolesSet["admin"] = struct{}{}
			}
		}
	}

	roles := make([]string, 0, len(rolesSet))
	for r := range rolesSet {
		roles = append(roles, r)
	}
	return roles
}
