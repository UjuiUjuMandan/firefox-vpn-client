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

const (
	proxyPassClaimTimeTolerance = time.Minute
	proxyPassClaimTimeMaxFuture = 2 * time.Hour
)

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

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("quota exceeded (HTTP 429): %s", readErrorBody(resp.Body))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian",
			StatusCode: resp.StatusCode,
			Body:       readErrorBody(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading guardian response: %w", err)
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
	if claims.Exp == 0 {
		return 0
	}

	rawExp := time.Unix(claims.Exp, 0)
	rawStart, hasStart := proxyPassClaimStartTime(claims)
	if hasStart {
		if !rawStart.Before(rawExp) {
			return 0
		}
		if withinTimeWindow(now, rawStart.Add(-proxyPassClaimTimeTolerance), rawExp.Add(proxyPassClaimTimeTolerance)) {
			return 0
		}
	} else if proxyPassExpirationLooksFresh(now, rawExp) {
		return 0
	}

	for _, offset := range proxyPassClaimTimeOffsetCandidates(now) {
		shiftedExp := rawExp.Add(offset)
		if hasStart {
			shiftedStart := rawStart.Add(offset)
			if withinTimeWindow(now, shiftedStart.Add(-proxyPassClaimTimeTolerance), shiftedExp.Add(proxyPassClaimTimeTolerance)) {
				return offset
			}
		} else if proxyPassExpirationLooksFresh(now, shiftedExp) {
			return offset
		}
	}
	return 0
}

func proxyPassClaimTimeOffsetCandidates(now time.Time) []time.Duration {
	seen := make(map[time.Duration]bool)
	candidates := make([]time.Duration, 0, 107)
	add := func(offset time.Duration) {
		if offset == 0 || seen[offset] {
			return
		}
		seen[offset] = true
		candidates = append(candidates, offset)
	}

	_, offsetSeconds := now.Zone()
	add(time.Duration(offsetSeconds) * time.Second)

	for minutes := -12 * 60; minutes <= 14*60; minutes += 15 {
		add(time.Duration(minutes) * time.Minute)
	}
	return candidates
}

func proxyPassClaimStartTime(claims ProxyPassClaims) (time.Time, bool) {
	switch {
	case claims.Nbf > 0:
		return time.Unix(claims.Nbf, 0), true
	case claims.Iat > 0:
		return time.Unix(claims.Iat, 0), true
	default:
		return time.Time{}, false
	}
}

func proxyPassExpirationLooksFresh(now, exp time.Time) bool {
	if exp.Before(now.Add(-proxyPassClaimTimeTolerance)) {
		return false
	}
	return exp.Sub(now) <= proxyPassClaimTimeMaxFuture
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

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian user info request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian user info",
			StatusCode: resp.StatusCode,
			Body:       readErrorBody(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian activate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian activate",
			StatusCode: resp.StatusCode,
			Body:       readErrorBody(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
