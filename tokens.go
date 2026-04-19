package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const tokenFileName = ".firefox-vpn-tokens.json"

type SavedTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ObtainedAt   time.Time `json:"obtained_at"`
	ExpiresIn    int       `json:"expires_in"`
}

func (s *SavedTokens) AccessTokenValid() bool {
	if s.AccessToken == "" {
		return false
	}
	expiry := s.ObtainedAt.Add(time.Duration(s.ExpiresIn) * time.Second)
	return time.Now().Before(expiry.Add(-60 * time.Second))
}

func tokenFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return tokenFileName
	}
	return filepath.Join(home, tokenFileName)
}

func loadTokens() (*SavedTokens, error) {
	data, err := os.ReadFile(tokenFilePath())
	if err != nil {
		return nil, err
	}
	var tokens SavedTokens
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

func saveTokens(tok *TokenResponse) error {
	saved := SavedTokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Scope:        tok.Scope,
		ObtainedAt:   time.Now(),
		ExpiresIn:    tok.ExpiresIn,
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	path := tokenFilePath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("saving tokens to %s: %w", path, err)
	}
	return nil
}

func deleteTokens() {
	os.Remove(tokenFilePath())
}
