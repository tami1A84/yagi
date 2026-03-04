package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TokenData holds the persisted OAuth tokens.
type TokenData struct {
	Provider     string    `json:"provider"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// IsExpired checks if the token has expired (with a 5-minute buffer).
func (t *TokenData) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(5 * time.Minute).After(t.ExpiresAt)
}

// AuthFile holds all stored authentications.
type AuthFile struct {
	Version int                  `json:"version"`
	Tokens  map[string]TokenData `json:"tokens"`
}

// GetToken returns the stored token for a provider, or nil.
func (af *AuthFile) GetToken(providerName string) *TokenData {
	if af == nil || af.Tokens == nil {
		return nil
	}
	t, ok := af.Tokens[providerName]
	if !ok {
		return nil
	}
	return &t
}

// SetToken stores or updates a token for a provider.
func (af *AuthFile) SetToken(providerName string, token TokenData) {
	if af.Tokens == nil {
		af.Tokens = make(map[string]TokenData)
	}
	af.Tokens[providerName] = token
}

// RemoveToken removes a provider's stored token.
func (af *AuthFile) RemoveToken(providerName string) {
	if af.Tokens != nil {
		delete(af.Tokens, providerName)
	}
}

func authFilePath(configDir string) string {
	return filepath.Join(configDir, "auth.json")
}

// LoadAuthFile reads the auth file from the config directory.
func LoadAuthFile(configDir string) (*AuthFile, error) {
	data, err := os.ReadFile(authFilePath(configDir))
	if err != nil {
		if os.IsNotExist(err) {
			return &AuthFile{Version: 1, Tokens: make(map[string]TokenData)}, nil
		}
		return nil, err
	}
	var af AuthFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("parsing auth file: %w", err)
	}
	if af.Tokens == nil {
		af.Tokens = make(map[string]TokenData)
	}
	return &af, nil
}

// SaveAuthFile writes the auth file to the config directory with 0600 permissions.
func SaveAuthFile(configDir string, af *AuthFile) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return err
	}
	// Write to temp file then rename for atomicity.
	path := authFilePath(configDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func init() {
	messageWriter = os.Stderr
}
