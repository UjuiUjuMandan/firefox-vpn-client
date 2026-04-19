package vpnclient

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
)

type LoginResponse struct {
	SessionToken string `json:"sessionToken"`
	UID          string `json:"uid"`
	Verified     bool   `json:"verified"`
	AuthAt       int64  `json:"authAt"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func deriveAuthPW(email, password string) ([]byte, error) {
	salt := []byte(protocolVersion + "quickStretch:" + email)
	quickStretchedPW := pbkdf2.Key([]byte(password), salt, pbkdf2Rounds, stretchedPWLen, sha256.New)

	hkdfSalt := []byte{0x00}
	info := []byte(protocolVersion + "authPW")
	hkdfReader := hkdf.New(sha256.New, quickStretchedPW, hkdfSalt, info)
	authPW := make([]byte, hkdfLen)
	if _, err := io.ReadFull(hkdfReader, authPW); err != nil {
		return nil, err
	}
	return authPW, nil
}

func deriveHawkCredentials(tokenHex, context string) (id string, key []byte, err error) {
	tokenBytes, err := hex.DecodeString(tokenHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid token hex: %w", err)
	}
	info := []byte(protocolVersion + context)
	hkdfReader := hkdf.New(sha256.New, tokenBytes, nil, info)
	out := make([]byte, 3*32)
	if _, err := io.ReadFull(hkdfReader, out); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(out[:32]), out[32:64], nil
}

func hawkHeader(method, rawURL, hawkID string, hawkKey []byte, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 6)
	rand.Read(nonce)
	nonceStr := hex.EncodeToString(nonce)
	ts := fmt.Sprintf("%d", time.Now().Unix())

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
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
		ts,
		nonceStr,
		strings.ToUpper(method),
		u.RequestURI(),
		u.Hostname(),
		port,
		payloadHash,
		"",
		"",
	}, "\n")

	mac := hmac.New(sha256.New, hawkKey)
	mac.Write([]byte(normalized))
	macStr := hex.EncodeToString(mac.Sum(nil))

	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, hawkID, ts, nonceStr, macStr)
	if payloadHash != "" {
		header += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}
	return header, nil
}

func fxaLogin(email, password string) (*LoginResponse, error) {
	authPW, err := deriveAuthPW(email, password)
	if err != nil {
		return nil, fmt.Errorf("deriving authPW: %w", err)
	}

	body := map[string]string{
		"email":  email,
		"authPW": hex.EncodeToString(authPW),
	}
	bodyJSON, _ := json.Marshal(body)

	loginURL := fxaAuthServer + "/account/login"
	resp, err := http.Post(loginURL, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(data))
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(data, &loginResp); err != nil {
		return nil, fmt.Errorf("parsing login response: %w", err)
	}
	return &loginResp, nil
}

func fxaOAuthToken(sessionToken string) (*TokenResponse, error) {
	hawkID, hawkKey, err := deriveHawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, fmt.Errorf("deriving hawk credentials: %w", err)
	}

	body := map[string]interface{}{
		"client_id":   firefoxClientID,
		"grant_type":  "fxa-credentials",
		"scope":       oauthScope,
		"access_type": "offline",
	}
	bodyJSON, _ := json.Marshal(body)

	tokenURL := fxaAuthServer + "/oauth/token"
	authHeader, err := hawkHeader("POST", tokenURL, hawkID, hawkKey, string(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("generating hawk header: %w", err)
	}

	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth token request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth token failed (HTTP %d): %s", resp.StatusCode, string(data))
	}

	var tok TokenResponse
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	return &tok, nil
}

func fxaRefreshToken(refreshToken string) (*TokenResponse, error) {
	body := map[string]interface{}{
		"client_id":     firefoxClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"scope":         oauthScope,
	}
	bodyJSON, _ := json.Marshal(body)

	tokenURL := fxaAuthServer + "/oauth/token"
	resp, err := http.Post(tokenURL, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(data))
	}

	var tok TokenResponse
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}
	// Refresh response may not include a new refresh_token; keep the old one
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return &tok, nil
}

func FxaLogin(email, password string) (*LoginResponse, error) {
	return fxaLogin(email, password)
}

func FxaOAuthToken(sessionToken string) (*TokenResponse, error) {
	return fxaOAuthToken(sessionToken)
}

func FxaRefreshToken(refreshToken string) (*TokenResponse, error) {
	return fxaRefreshToken(refreshToken)
}
