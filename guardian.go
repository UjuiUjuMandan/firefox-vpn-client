package vpnclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GuardianEndpointDefault is the default Guardian API endpoint used when no
// explicit endpoint is configured.
const GuardianEndpointDefault = "https://vpn.mozilla.org"

const (
	proxyPassClaimTimeTolerance = time.Minute
	proxyPassClaimTimeMaxFuture = 2 * time.Hour

	// claimOffsetMinMinutes is the lower bound of the local-wall-clock
	// correction candidate sweep, in minutes relative to UTC.
	claimOffsetMinMinutes = -12 * 60

	// claimOffsetMaxMinutes is the upper bound of the local-wall-clock
	// correction candidate sweep, in minutes relative to UTC.
	claimOffsetMaxMinutes = 14 * 60

	// claimOffsetStepMinutes is the granularity of the candidate sweep.
	claimOffsetStepMinutes = 15

	// claimOffsetCandidateCapacity is an upper bound on the number of
	// candidates the sweep can produce (one zone offset plus the sweep
	// itself, with headroom).
	claimOffsetCandidateCapacity = 107

	// jwtSegmentCount is the number of dot-separated segments in a JWT.
	jwtSegmentCount = 3
)

// ProxyPassClaims are the JWT claims of a Guardian-issued proxy pass.
type ProxyPassClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

// ProxyPassInfo is a Guardian proxy pass: the raw JWT, its decoded claims,
// the account quota headers, and the detected local clock correction.
type ProxyPassInfo struct {
	RawToken        string
	Claims          ProxyPassClaims
	QuotaMax        string
	QuotaLeft       string
	QuotaReset      string
	claimTimeOffset time.Duration
}

// NotBefore returns the corrected not-before time of the proxy pass.
func (p *ProxyPassInfo) NotBefore() time.Time { return p.claimTime(p.Claims.Nbf) }

// ExpiresAt returns the corrected expiry time of the proxy pass.
func (p *ProxyPassInfo) ExpiresAt() time.Time { return p.claimTime(p.Claims.Exp) }

// ClaimTimeCorrection returns the clock correction applied to the claim
// times, computed against the local wall clock when the pass was fetched.
func (p *ProxyPassInfo) ClaimTimeCorrection() time.Duration {
	return p.claimTimeOffset
}

// BearerToken returns the Authorization header value for the proxy pass.
func (p *ProxyPassInfo) BearerToken() string { return "Bearer " + p.RawToken }

// Entitlement is the account's Guardian subscription status.
type Entitlement struct {
	Subscribed       bool   `json:"subscribed"`
	UID              int    `json:"uid"`
	MaxBytes         string `json:"maxBytes"` //nolint:tagliatelle // upstream Guardian wire format is camelCase here
	LimitedBandwidth bool   `json:"limited_bandwidth"`
}

type proxyPassResponse struct {
	Token string `json:"token"`
}

// ErrQuotaExceeded signals that the account's monthly proxy quota is
// exhausted (Guardian responds with HTTP 429).
var ErrQuotaExceeded = errors.New("quota exceeded")

// ErrTokenInvalid signals that Guardian rejected the access token
// (HTTP 401/403), e.g. the account has no active subscription. Callers
// with a session token pool should rotate to the next token on this error.
var ErrTokenInvalid = errors.New("token invalid")

// errEmptyGuardianToken signals a 200 response without a proxy pass token.
var errEmptyGuardianToken = errors.New("empty token in guardian response")

// errInvalidJWT signals a proxy pass JWT with an unexpected segment count.
var errInvalidJWT = errors.New("invalid JWT")

// GuardianHTTPError is a non-2xx Guardian response.
type GuardianHTTPError struct {
	Operation  string
	StatusCode int
	Body       string
}

// Error renders the failed operation with its HTTP status and body.
func (e *GuardianHTTPError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d: %s", e.Operation, e.StatusCode, e.Body)
}

func fetchProxyPass(ctx context.Context, endpoint, accessToken string) (*ProxyPassInfo, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}

	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating guardian token request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w (HTTP 429): %s", ErrQuotaExceeded, readErrorBody(resp.Body))
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w (HTTP %d): %s", ErrTokenInvalid, resp.StatusCode, readErrorBody(resp.Body))
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

	err = json.Unmarshal(body, &passResp)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy pass response: %w", err)
	}

	if passResp.Token == "" {
		return nil, errEmptyGuardianToken
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

		if withinTimeWindow(now,
			rawStart.Add(-proxyPassClaimTimeTolerance),
			rawExp.Add(proxyPassClaimTimeTolerance)) {
			return 0
		}
	} else if proxyPassExpirationLooksFresh(now, rawExp) {
		return 0
	}

	for _, offset := range proxyPassClaimTimeOffsetCandidates(now) {
		shiftedExp := rawExp.Add(offset)

		if hasStart {
			shiftedStart := rawStart.Add(offset)
			shiftedStartWindow := shiftedStart.Add(-proxyPassClaimTimeTolerance)

			shiftedExpWindow := shiftedExp.Add(proxyPassClaimTimeTolerance)

			if withinTimeWindow(now, shiftedStartWindow, shiftedExpWindow) {
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
	candidates := make([]time.Duration, 0, claimOffsetCandidateCapacity)
	add := func(offset time.Duration) {
		if offset == 0 || seen[offset] {
			return
		}

		seen[offset] = true

		candidates = append(candidates, offset)
	}

	_, offsetSeconds := now.Zone()
	add(time.Duration(offsetSeconds) * time.Second)

	for minutes := claimOffsetMinMinutes; minutes <= claimOffsetMaxMinutes; minutes += claimOffsetStepMinutes {
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

//nolint:dupl // GET/POST twin of fetchUserInfo below; kept separate so each request flow reads linearly
func fetchUserInfo(ctx context.Context, endpoint, accessToken string) (*Entitlement, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}

	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/status"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating guardian user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian user info request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian user info",
			StatusCode: resp.StatusCode,
			Body:       readErrorBody(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading guardian user info response: %w", err)
	}

	var ent Entitlement

	err = json.Unmarshal(body, &ent)
	if err != nil {
		return nil, fmt.Errorf("parsing entitlement: %w", err)
	}

	return &ent, nil
}

//nolint:dupl // POST twin of fetchUserInfo above; kept separate so each request flow reads linearly
func activateGuardian(ctx context.Context, endpoint, accessToken string) (*Entitlement, error) {
	if endpoint == "" {
		endpoint = GuardianEndpointDefault
	}

	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/activate"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating guardian activate request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	applyMozillaVPNHeaders(req)

	resp, err := doControlPlane(req)
	if err != nil {
		return nil, fmt.Errorf("guardian activate request failed: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &GuardianHTTPError{
			Operation:  "guardian activate",
			StatusCode: resp.StatusCode,
			Body:       readErrorBody(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading guardian activate response: %w", err)
	}

	var ent Entitlement

	err = json.Unmarshal(body, &ent)
	if err != nil {
		return nil, fmt.Errorf("parsing activation entitlement: %w", err)
	}

	return &ent, nil
}

func parseJWTClaims(token string) (*ProxyPassClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != jwtSegmentCount {
		return nil, fmt.Errorf("%w: expected %d parts, got %d", errInvalidJWT, jwtSegmentCount, len(parts))
	}

	payload := parts[1]
	// JWT segments use unpadded base64url; RawURLEncoding handles the
	// missing padding without manual "% 4" arithmetic.
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims ProxyPassClaims

	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT claims JSON: %w", err)
	}

	return &claims, nil
}

func (p *ProxyPassInfo) claimTime(sec int64) time.Time {
	return time.Unix(sec, 0).Add(p.claimTimeOffset)
}

// FetchProxyPass fetches a Guardian proxy pass for the access token.
func FetchProxyPass(ctx context.Context, endpoint, accessToken string) (*ProxyPassInfo, error) {
	return fetchProxyPass(ctx, endpoint, accessToken)
}

// FetchUserInfo queries the account's Guardian entitlement status.
func FetchUserInfo(ctx context.Context, endpoint, accessToken string) (*Entitlement, error) {
	return fetchUserInfo(ctx, endpoint, accessToken)
}

// ActivateGuardian activates the account for Firefox VPN proxy access.
func ActivateGuardian(ctx context.Context, endpoint, accessToken string) (*Entitlement, error) {
	return activateGuardian(ctx, endpoint, accessToken)
}
