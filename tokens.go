package vpnclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// tokenFileName is the saved token file name inside the user's home
// directory; the name merely refers to tokens, it holds none itself.
const tokenFileName = ".firefox-vpn-tokens.json" //nolint:gosec // G101: a file name, not a credential

// fileModeOwnerOnly is the permission mask for files holding tokens.
const fileModeOwnerOnly = 0600

// accessTokenRefreshLead is how long before expiry a saved access token is
// considered stale.
const accessTokenRefreshLead = 60 * time.Second

// SavedTokens is the OAuth token file persisted in the user's home
// directory. The field names reference token values; the struct itself is a
// plain DTO.
type SavedTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ObtainedAt   time.Time `json:"obtained_at"`
	ExpiresIn    int       `json:"expires_in"`
}

// AccessTokenValid reports whether the saved access token is still valid
// with a safety lead before its expiry.
func (s *SavedTokens) AccessTokenValid() bool {
	if s.AccessToken == "" {
		return false
	}

	expiry := s.ObtainedAt.Add(time.Duration(s.ExpiresIn) * time.Second)

	return time.Now().Before(expiry.Add(-accessTokenRefreshLead))
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
		return nil, fmt.Errorf("reading token file: %w", err)
	}

	var tokens SavedTokens

	err = json.Unmarshal(data, &tokens)
	if err != nil {
		return nil, fmt.Errorf("parsing token file: %w", err)
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

	// G117: DTO fields; the secrets are the runtime values, not the type.
	data, err := json.MarshalIndent(saved, "", "  ") //nolint:gosec // G117
	if err != nil {
		return fmt.Errorf("marshaling tokens: %w", err)
	}

	path := tokenFilePath()

	err = writePrivateFile(path, data)
	if err != nil {
		return fmt.Errorf("saving tokens to %s: %w", path, err)
	}

	return nil
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp token file: %w", err)
	}

	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	err = tmp.Chmod(fileModeOwnerOnly)
	if err != nil {
		_ = tmp.Close()

		return fmt.Errorf("restricting temp token file permissions: %w", err)
	}

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()

		return fmt.Errorf("writing temp token file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("closing temp token file: %w", err)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replacing token file: %w", err)
		}

		retryErr := os.Rename(tmpPath, path)
		if retryErr != nil {
			return fmt.Errorf("replacing token file after retry: %w", retryErr)
		}
	}

	err = os.Chmod(path, fileModeOwnerOnly)
	if err != nil {
		return fmt.Errorf("restricting token file permissions: %w", err)
	}

	return nil
}

func deleteTokens() {
	_ = os.Remove(tokenFilePath())
}

// TokenFilePath returns the absolute path of the saved token file.
func TokenFilePath() string {
	return tokenFilePath()
}

// LoadTokens loads the persisted OAuth tokens from the user's home
// directory.
func LoadTokens() (*SavedTokens, error) {
	return loadTokens()
}

// SaveTokens persists OAuth tokens to the user's home directory with
// owner-only permissions.
func SaveTokens(tok *TokenResponse) error {
	return saveTokens(tok)
}

// DeleteTokens removes the persisted token file, ignoring absence.
func DeleteTokens() {
	deleteTokens()
}
