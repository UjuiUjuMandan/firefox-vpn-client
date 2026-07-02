package vpnclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const GuardianEndpointDefault = "https://vpn.mozilla.org"

type ProxyPassClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

type ProxyPassInfo struct {
	RawToken        string
	Claims          ProxyPassClaims
	QuotaMax        string
	QuotaLeft       string
	QuotaReset      string
	claimTimeOffset time.Duration
}

func (p *ProxyPassInfo) NotBefore() time.Time { return p.claimTime(p.Claims.Nbf) }
func (p *ProxyPassInfo) ExpiresAt() time.Time { return p.claimTime(p.Claims.Exp) }

func (p *ProxyPassInfo) claimTime(sec int64) time.Time {
	return time.Unix(sec, 0).Add(p.claimTimeOffset)
}

func (p *ProxyPassInfo) ClaimTimeCorrection() time.Duration {
	return p.claimTimeOffset
}

func (p *ProxyPassInfo) BearerToken() string { return "Bearer " + p.RawToken }

type Entitlement struct {
	Subscribed       bool   `json:"subscribed"`
	UID              int    `json:"uid"`
	MaxBytes         string `json:"maxBytes"`
	LimitedBandwidth bool   `json:"limited_bandwidth"`
}

type proxyPassResponse struct {
	Token string `json:"token"`
}

type GuardianHTTPError struct {
	Operation  string
	StatusCode int
	Body       string
}

func (e *GuardianHTTPError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d: %s", e.Operation, e.StatusCode, e.Body)
}

func fetchProxyPass(endpoint, accessToken string) (*ProxyPassInfo, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/token"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

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
		return nil, &GuardianHTTPError{
			Operation:  "guardian",
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
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
		RawToken:        passResp.Token,
		Claims:          *claims,
		QuotaMax:        resp.Header.Get("X-Quota-Limit"),
		QuotaLeft:       resp.Header.Get("X-Quota-Remaining"),
		QuotaReset:      resp.Header.Get("X-Quota-Reset"),
		claimTimeOffset: detectProxyPassClaimTimeOffset(*claims, time.Now()),
	}
	return info, nil
}

func detectProxyPassClaimTimeOffset(claims ProxyPassClaims, now time.Time) time.Duration {
	if claims.Nbf == 0 || claims.Exp == 0 || claims.Exp <= claims.Nbf {
		return 0
	}

	rawNbf := time.Unix(claims.Nbf, 0)
	rawExp := time.Unix(claims.Exp, 0)
	tolerance := time.Minute
	if withinTimeWindow(now, rawNbf.Add(-tolerance), rawExp.Add(tolerance)) {
		return 0
	}

	_, offsetSeconds := now.Zone()
	if offsetSeconds == 0 {
		return 0
	}
	offset := time.Duration(offsetSeconds) * time.Second
	shiftedNbf := rawNbf.Add(offset)
	shiftedExp := rawExp.Add(offset)
	if withinTimeWindow(now, shiftedNbf.Add(-tolerance), shiftedExp.Add(tolerance)) {
		return offset
	}
	return 0
}

func withinTimeWindow(t, start, end time.Time) bool {
	return !t.Before(start) && !t.After(end)
}

func fetchUserInfo(endpoint, accessToken string) (*Entitlement, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/status"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

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
		return nil, &GuardianHTTPError{
			Operation:  "guardian user info",
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return nil, fmt.Errorf("parsing entitlement: %w", err)
	}
	return &ent, nil
}

func activateGuardian(endpoint, accessToken string) (*Entitlement, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/activate"

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardian activate request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian activate",
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	var ent Entitlement
	if err := json.Unmarshal(body, &ent); err != nil {
		return nil, fmt.Errorf("parsing activation entitlement: %w", err)
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

func FetchProxyPass(endpoint, accessToken string) (*ProxyPassInfo, error) {
	return fetchProxyPass(endpoint, accessToken)
}

func FetchUserInfo(endpoint, accessToken string) (*Entitlement, error) {
	return fetchUserInfo(endpoint, accessToken)
}

func ActivateGuardian(endpoint, accessToken string) (*Entitlement, error) {
	return activateGuardian(endpoint, accessToken)
}
