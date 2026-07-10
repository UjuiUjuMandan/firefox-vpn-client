package vpnclient

import (
	"encoding/json"
	"errors"
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
	if err := writePrivateFile(path, data); err != nil {
		return fmt.Errorf("saving tokens to %s: %w", path, err)
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if retryErr := os.Rename(tmpPath, path); retryErr != nil {
			return retryErr
		}
	}
	return os.Chmod(path, 0600)
}

func deleteTokens() {
	os.Remove(tokenFilePath())
}

func TokenFilePath() string {
	return tokenFilePath()
}

func LoadTokens() (*SavedTokens, error) {
	return loadTokens()
}

func SaveTokens(tok *TokenResponse) error {
	return saveTokens(tok)
}

func DeleteTokens() {
	deleteTokens()
}
