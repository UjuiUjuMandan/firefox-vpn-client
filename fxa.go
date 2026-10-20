package vpnclient

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	fxaAuthServer   = "https://api.accounts.firefox.com/v1"
	firefoxClientID = "5882386c6d801776"
	oauthScope      = "profile https://identity.mozilla.com/apps/vpn"
	protocolVersion = "identity.mozilla.com/picl/v1/"
	pbkdf2Rounds    = 1000
	stretchedPWLen  = 32
	hkdfLen         = 32

	// challengeDrainLimit caps how much of a 406 response body is drained
	// before re-solving the challenge.
	challengeDrainLimit = 4096

	// maxChallengeAttempts bounds how many times an FxA call re-solves the
	// Fastly anti-bot challenge; with rotating-exit proxies a solved cookie
	// can be rejected when the API request leaves through another IP.
	maxChallengeAttempts = 5

	// fxaCallMinBudget is the minimum wall-clock budget an FxA call gets:
	// the caller's per-request timeout is often shorter than a full
	// challenge-solving round trip.
	fxaCallMinBudget = 90 * time.Second

	// verificationMethodEmail2FA tells FxA to deliver the sign-in
	// confirmation as a code emailed to the account instead of the
	// default confirmation link: the link redirects through
	// accounts.firefox.com, which warns about non-Firefox browsers and
	// cannot be followed from this CLI client.
	verificationMethodEmail2FA = "email-2fa"

	// fxaErrnoInvalidParameter is FxA's "Invalid parameter" errno; a
	// deployment that does not accept verificationMethod in the login
	// body answers with it, so we fall back to a plain login.
	fxaErrnoInvalidParameter = 107

	// hawkKeyMaterialLen is the total number of key bytes the hawk
	// credentials derivation produces (id, key, and extra material).
	hawkKeyMaterialLen = 3 * 32

	// hawkNonceLen is the random nonce length used in the hawk header.
	hawkNonceLen = 6
)

// LoginResponse is the FxA login response. The FxA account API uses
// camelCase JSON keys here, unlike the snake_case OAuth token endpoint.
type LoginResponse struct {
	SessionToken       string `json:"sessionToken"` //nolint:tagliatelle // upstream FxA wire format is camelCase here
	UID                string `json:"uid"`
	Verified           bool   `json:"verified"`
	AuthAt             int64  `json:"authAt"`             //nolint:tagliatelle // upstream FxA wire format
	VerificationMethod string `json:"verificationMethod"` //nolint:tagliatelle // upstream FxA wire format
	VerificationReason string `json:"verificationReason"` //nolint:tagliatelle // upstream FxA wire format
}

// TokenResponse is the OAuth token response from the FxA oauth/token
// endpoint, which uses snake_case JSON keys.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// fxaAPIError carries a non-2xx FxA response so callers can branch on the
// API errno (e.g. invalid parameter) instead of parsing error strings.
type fxaAPIError struct {
	Status int
	Errno  int
	Body   string
}

func (e *fxaAPIError) Error() string {
	if e.Errno != 0 {
		return fmt.Sprintf("FxA error (HTTP %d, errno %d): %s", e.Status, e.Errno, e.Body)
	}

	return fmt.Sprintf("FxA request failed (HTTP %d): %s", e.Status, e.Body)
}

func newFxaAPIError(status int, body []byte) *fxaAPIError {
	var parsed struct {
		Errno int `json:"errno"`
	}

	_ = json.Unmarshal(body, &parsed)

	return &fxaAPIError{Status: status, Errno: parsed.Errno, Body: string(body)}
}

var (
	// errChallengeStillFailing signals that re-solving the Fastly
	// anti-bot challenge did not clear the HTTP 406 edge response.
	errChallengeStillFailing = errors.New("Fastly anti-bot challenge still failing") //nolint:staticcheck // proper noun

	// errVerificationFailed signals a non-OK session verification
	// response from FxA.
	errVerificationFailed = errors.New("verification failed")
)

func deriveAuthPW(email, password string) ([]byte, error) {
	salt := []byte(protocolVersion + "quickStretch:" + email)
	quickStretchedPW := pbkdf2.Key([]byte(password), salt, pbkdf2Rounds, stretchedPWLen, sha256.New)

	hkdfSalt := []byte{0x00}
	info := []byte(protocolVersion + "authPW")
	hkdfReader := hkdf.New(sha256.New, quickStretchedPW, hkdfSalt, info)

	authPW := make([]byte, hkdfLen)

	_, err := io.ReadFull(hkdfReader, authPW)
	if err != nil {
		return nil, fmt.Errorf("reading stretched password: %w", err)
	}

	return authPW, nil
}

func deriveHawkCredentials(tokenHex, context string) (string, []byte, error) {
	tokenBytes, err := hex.DecodeString(tokenHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid token hex: %w", err)
	}

	info := []byte(protocolVersion + context)
	hkdfReader := hkdf.New(sha256.New, tokenBytes, nil, info)

	out := make([]byte, hawkKeyMaterialLen)

	_, err = io.ReadFull(hkdfReader, out)
	if err != nil {
		return "", nil, fmt.Errorf("reading hawk key material: %w", err)
	}

	return hex.EncodeToString(out[:32]), out[32:64], nil
}

func hawkHeader(method, rawURL, hawkID string, hawkKey []byte, payload string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing request URL: %w", err)
	}

	nonce := make([]byte, hawkNonceLen)

	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	nonceStr := hex.EncodeToString(nonce)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	var payloadHash string

	if payload != "" {
		h := sha256.New()
		h.Write([]byte("hawk.1.payload\napplication/json\n"))
		h.Write([]byte(payload))
		h.Write([]byte("\n"))
		payloadHash = hex.EncodeToString(h.Sum(nil))
	}

	normalized := strings.Join([]string{
		"hawk.1.header",
		timestamp,
		nonceStr,
		strings.ToUpper(method),
		parsedURL.RequestURI(),
		parsedURL.Hostname(),
		port,
		payloadHash,
		"",
		"",
	}, "\n")

	mac := hmac.New(sha256.New, hawkKey)
	mac.Write([]byte(normalized))
	macStr := hex.EncodeToString(mac.Sum(nil))

	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, hawkID, timestamp, nonceStr, macStr)
	if payloadHash != "" {
		header += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}

	return header, nil
}

// fxaDo sends an FxA API request built by newRequest, transparently solving
// the Fastly anti-bot client challenge when the edge answers HTTP 406 (empty
// body, no FxA error payload). The request factory is invoked again after
// each successful solve because request bodies are single-use readers.
func fxaDo(ctx context.Context, newRequest func() (*http.Request, error)) (*http.Response, error) {
	ctx, cancel := contextWithMinDeadline(ctx, fxaCallMinBudget)
	defer cancel()

	for attempt := 1; attempt <= maxChallengeAttempts; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}

		resp, err := doControlPlane(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusNotAcceptable {
			return resp, nil
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, challengeDrainLimit))
		_ = resp.Body.Close()

		err = solveFastlyChallenge(ctx)
		if err != nil {
			return nil, fmt.Errorf("Fastly anti-bot challenge: %w", err) //nolint:staticcheck // ST1005: Fastly is a proper noun
		}
	}

	return nil, fmt.Errorf("%w after %d attempts (HTTP 406)", errChallengeStillFailing, maxChallengeAttempts)
}

func fxaLogin(ctx context.Context, email, password string) (*LoginResponse, error) {
	loginResp, err := fxaLoginAttempt(ctx, email, password, verificationMethodEmail2FA)
	if err != nil {
		var apiErr *fxaAPIError
		if errors.As(err, &apiErr) && apiErr.Errno == fxaErrnoInvalidParameter {
			return fxaLoginAttempt(ctx, email, password, "")
		}

		return nil, err
	}

	return loginResp, nil
}

func fxaLoginAttempt(ctx context.Context, email, password, verificationMethod string) (*LoginResponse, error) {
	authPW, err := deriveAuthPW(email, password)
	if err != nil {
		return nil, fmt.Errorf("deriving authPW: %w", err)
	}

	body := map[string]string{
		"email":  email,
		"authPW": hex.EncodeToString(authPW),
	}
	if verificationMethod != "" {
		body["verificationMethod"] = verificationMethod
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling login body: %w", err)
	}

	loginURL := fxaAuthServer + "/account/login"

	resp, err := fxaDo(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, fmt.Errorf("creating login request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		applyMozillaVPNHeaders(req)

		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError(resp.StatusCode, data)
	}

	var loginResp LoginResponse

	err = json.Unmarshal(data, &loginResp)
	if err != nil {
		return nil, fmt.Errorf("parsing login response: %w", err)
	}

	return &loginResp, nil
}

// fxaVerifySession submits the email confirmation code for an unverified
// session created by fxaLogin; FxA sends the code to the account email at
// login time.
func fxaVerifySession(ctx context.Context, sessionToken, code string) error {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return fmt.Errorf("deriving hawk credentials: %w", err)
	}

	body := map[string]string{"code": code}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling verify code body: %w", err)
	}

	verifyURL := fxaAuthServer + "/session/verify_code"

	resp, err := fxaDo(ctx, func() (*http.Request, error) {
		authHeader, err := hawkHeader("POST", verifyURL, hawkID, hawkKey, string(bodyJSON))
		if err != nil {
			return nil, fmt.Errorf("generating hawk header: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, fmt.Errorf("creating verify code request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authHeader)
		applyMozillaVPNHeaders(req)

		return req, nil
	})
	if err != nil {
		return fmt.Errorf("verify code request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (HTTP %d): %s", errVerificationFailed, resp.StatusCode, truncate(string(data)))
	}

	return nil
}

func fxaOAuthToken(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, fmt.Errorf("deriving hawk credentials: %w", err)
	}

	body := map[string]any{
		"client_id":   firefoxClientID,
		"grant_type":  "fxa-credentials",
		"scope":       oauthScope,
		"access_type": "offline",
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling oauth token body: %w", err)
	}

	tokenURL := fxaAuthServer + "/oauth/token"

	resp, err := fxaDo(ctx, func() (*http.Request, error) {
		authHeader, err := hawkHeader("POST", tokenURL, hawkID, hawkKey, string(bodyJSON))
		if err != nil {
			return nil, fmt.Errorf("generating hawk header: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, fmt.Errorf("creating oauth token request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authHeader)
		applyMozillaVPNHeaders(req)

		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("oauth token request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError(resp.StatusCode, []byte(readErrorBody(resp.Body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tok TokenResponse

	err = json.Unmarshal(data, &tok)
	if err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	return &tok, nil
}

func fxaRefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body := map[string]any{
		"client_id":     firefoxClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"scope":         oauthScope,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling refresh body: %w", err)
	}

	tokenURL := fxaAuthServer + "/oauth/token"

	resp, err := fxaDo(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(bodyJSON)))
		if err != nil {
			return nil, fmt.Errorf("creating refresh request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		applyMozillaVPNHeaders(req)

		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, newFxaAPIError(resp.StatusCode, []byte(readErrorBody(resp.Body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}

	var tok TokenResponse

	err = json.Unmarshal(data, &tok)
	if err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}

	// Refresh response may not include a new refresh_token; keep the old one
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}

	return &tok, nil
}

// FxaLogin logs in to Firefox Accounts with email and password and returns
// the login response, which may require email verification.
func FxaLogin(ctx context.Context, email, password string) (*LoginResponse, error) {
	return fxaLogin(ctx, email, password)
}

// FxaVerifySession submits the emailed verification code for an unverified
// FxA login session.
func FxaVerifySession(ctx context.Context, sessionToken, code string) error {
	return fxaVerifySession(ctx, sessionToken, code)
}

// FxaOAuthToken exchanges a session token for OAuth access and refresh
// tokens with the profile+VPN scope.
func FxaOAuthToken(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	return fxaOAuthToken(ctx, sessionToken)
}

// FxaRefreshToken exchanges a refresh token for fresh OAuth tokens.
func FxaRefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return fxaRefreshToken(ctx, refreshToken)
}
