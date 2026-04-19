package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const guardianEndpointDefault = "https://vpn.mozilla.org"

type ProxyPassClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

type ProxyPassInfo struct {
	RawToken  string
	Claims    ProxyPassClaims
	QuotaMax  string
	QuotaLeft string
	QuotaReset string
}

func (p *ProxyPassInfo) NotBefore() time.Time { return time.Unix(p.Claims.Nbf, 0) }
func (p *ProxyPassInfo) ExpiresAt() time.Time { return time.Unix(p.Claims.Exp, 0) }

func (p *ProxyPassInfo) BearerToken() string { return "Bearer " + p.RawToken }

type Entitlement struct {
	Subscribed bool   `json:"subscribed"`
	UID        int    `json:"uid"`
	MaxBytes   string `json:"maxBytes"`
}

type proxyPassResponse struct {
	Token string `json:"token"`
}

func fetchProxyPass(endpoint, accessToken string) (*ProxyPassInfo, error) {
	if endpoint == "" {
		endpoint = guardianEndpointDefault
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/token"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardian request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading guardian response: %w", err)
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("quota exceeded (HTTP 429): %s", string(body))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardian returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var passResp proxyPassResponse
	if err := json.Unmarshal(body, &passResp); err != nil {
		return nil, fmt.Errorf("parsing proxy pass response: %w", err)
	}
	if passResp.Token == "" {
		return nil, fmt.Errorf("empty token in guardian response")
	}

	claims, err := parseJWTClaims(passResp.Token)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	info := &ProxyPassInfo{
		RawToken:   passResp.Token,
		Claims:     *claims,
		QuotaMax:   resp.Header.Get("X-Quota-Limit"),
		QuotaLeft:  resp.Header.Get("X-Quota-Remaining"),
		QuotaReset: resp.Header.Get("X-Quota-Reset"),
	}
	return info, nil
}

func fetchUserInfo(endpoint, accessToken string) (*Entitlement, error) {
	if endpoint == "" {
		endpoint = guardianEndpointDefault
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/status"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardian user info request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardian user info returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return nil, fmt.Errorf("parsing entitlement: %w", err)
	}
	return &ent, nil
}

func parseJWTClaims(token string) (*ProxyPassClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard base64 as fallback
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("decoding JWT payload: %w", err)
		}
	}

	var claims ProxyPassClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims JSON: %w", err)
	}
	return &claims, nil
}
