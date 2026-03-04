package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/yagi-agent/yagi/auth"
)

var authFile *auth.AuthFile

// loadAuth loads stored authentication tokens from the config directory.
func loadAuth(configDir string) error {
	af, err := auth.LoadAuthFile(configDir)
	if err != nil {
		return err
	}
	authFile = af
	return nil
}

// promptAuthMethod shows an interactive menu to choose authentication method.
// Returns "oauth" or "apikey".
func promptAuthMethod(providerName string) string {
	fmt.Fprintf(os.Stderr, "\nHow would you like to authenticate with %s?\n\n", providerName)
	fmt.Fprintf(os.Stderr, "  1. Claude.ai (Standard subscription)\n")
	fmt.Fprintf(os.Stderr, "  2. API key (environment variable or -key flag)\n\n")

	response, err := readFromTTY("Choose [1/2]: ")
	if err != nil {
		return "apikey"
	}
	response = strings.TrimSpace(response)
	if response == "1" {
		return "oauth"
	}
	return "apikey"
}

// resolveAPIKeyWithAuth extends the existing key resolution to check
// for stored OAuth tokens. Priority: -key flag > env var > OAuth token.
func resolveAPIKeyWithAuth(configDir string, p *Provider, apiKeyFlag string) string {
	if apiKeyFlag != "" {
		return apiKeyFlag
	}

	if p.EnvKey != "" {
		if key := os.Getenv(p.EnvKey); key != "" {
			return key
		}
	}

	if authFile != nil {
		oauthName := p.Name
		if p.OAuthRef != "" {
			oauthName = p.OAuthRef
		}
		if token := authFile.GetToken(oauthName); token != nil {
			if !token.IsExpired() {
				return token.AccessToken
			}
			if oauthCfg, ok := auth.DefaultOAuthProviders[oauthName]; ok {
				newToken, err := auth.RefreshToken(context.Background(), oauthCfg, token)
				if err == nil {
					authFile.SetToken(oauthName, *newToken)
					_ = auth.SaveAuthFile(configDir, authFile)
					return newToken.AccessToken
				}
			}
		}
	}

	return ""
}

// runLogin performs the OAuth login flow for a provider.
func runLogin(configDir, providerName string) error {
	oauthCfg, ok := auth.DefaultOAuthProviders[providerName]
	if !ok {
		return fmt.Errorf("no OAuth configuration for provider %q", providerName)
	}

	token, err := auth.Login(context.Background(), oauthCfg)
	if err != nil {
		return err
	}

	if authFile == nil {
		authFile = &auth.AuthFile{Version: 1, Tokens: map[string]auth.TokenData{}}
	}
	authFile.SetToken(providerName, *token)
	return auth.SaveAuthFile(configDir, authFile)
}

// runLogout clears stored OAuth tokens for a provider.
func runLogout(configDir, providerName string) error {
	if authFile == nil {
		return fmt.Errorf("no authentication data found")
	}

	authFile.RemoveToken(providerName)
	return auth.SaveAuthFile(configDir, authFile)
}
