package auth

// DefaultOAuthProviders contains built-in OAuth configurations.
// Currently only Anthropic (Claude.ai) is supported.
var DefaultOAuthProviders = map[string]OAuthConfig{
	"anthropic": {
		ProviderName: "anthropic",
		ClientID:     "yagi-cli",
		AuthURL:      "https://console.anthropic.com/oauth/authorize",
		TokenURL:     "https://console.anthropic.com/oauth/token",
		Scopes:       []string{"chat"},
		CallbackPort: 19534,
	},
}
