package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// OAuthConfig defines endpoints for a provider's OAuth flow.
type OAuthConfig struct {
	ProviderName string   `json:"provider_name"`
	ClientID     string   `json:"client_id"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	Scopes       []string `json:"scopes"`
	CallbackPort int      `json:"callback_port,omitempty"`
}

// Login performs the full OAuth Authorization Code flow with PKCE.
// It starts a local callback server, opens the browser, waits for
// the authorization code, and exchanges it for tokens.
func Login(ctx context.Context, cfg OAuthConfig) (*TokenData, error) {
	verifier, challenge := generatePKCE()

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	listener, resultCh, err := startCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authURL := buildAuthURL(cfg, state, challenge, redirectURI)

	fmt.Fprintf(messageWriter, "\nOpening browser for authentication...\n")
	fmt.Fprintf(messageWriter, "If the browser doesn't open, visit this URL:\n\n  %s\n\n", authURL)

	_ = openBrowser(authURL)

	select {
	case result := <-resultCh:
		if result.Error != "" {
			return nil, fmt.Errorf("authorization failed: %s", result.Error)
		}
		return exchangeCode(ctx, cfg, result.Code, verifier, redirectURI)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authentication timed out (5 minutes)")
	}
}

// RefreshToken exchanges a refresh token for a new access token.
func RefreshToken(ctx context.Context, cfg OAuthConfig, token *TokenData) (*TokenData, error) {
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {cfg.ClientID},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp, cfg.ProviderName, token.RefreshToken)
}

func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

type callbackResult struct {
	Code  string
	Error string
}

func startCallbackServer(ctx context.Context, expectedState string) (net.Listener, <-chan callbackResult, error) {
	port := 19534
	var listener net.Listener
	var err error
	for i := 0; i < 10; i++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+i))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("could not bind callback server: %w", err)
	}

	ch := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errMsg := q.Get("error"); errMsg != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><body><h2>Authentication failed</h2><p>%s</p></body></html>`, errMsg)
			ch <- callbackResult{Error: errMsg}
			go server.Shutdown(context.Background())
			return
		}

		if q.Get("state") != expectedState {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><body><h2>Authentication failed</h2><p>State mismatch. Please try again with /login.</p></body></html>`)
			ch <- callbackResult{Error: "state mismatch"}
			go server.Shutdown(context.Background())
			return
		}

		code := q.Get("code")
		if code == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><body><h2>Authentication failed</h2><p>No authorization code received.</p></body></html>`)
			ch <- callbackResult{Error: "no authorization code"}
			go server.Shutdown(context.Background())
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><h2>Authentication successful!</h2><p>You can close this tab and return to yagi.</p><script>window.close()</script></body></html>`)
		ch <- callbackResult{Code: code}
		go server.Shutdown(context.Background())
	})

	go server.Serve(listener)

	return listener, ch, nil
}

func buildAuthURL(cfg OAuthConfig, state, challenge, redirectURI string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if len(cfg.Scopes) > 0 {
		params.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	return cfg.AuthURL + "?" + params.Encode()
}

func exchangeCode(ctx context.Context, cfg OAuthConfig, code, verifier, redirectURI string) (*TokenData, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp, cfg.ProviderName, "")
}

func parseTokenResponse(resp *http.Response, providerName, fallbackRefreshToken string) (*TokenData, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}

	token := &TokenData{
		Provider:     providerName,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
	}
	if tokenResp.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	if token.RefreshToken == "" && fallbackRefreshToken != "" {
		token.RefreshToken = fallbackRefreshToken
	}
	return token, nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

// messageWriter is where informational messages are written.
// Defaults to os.Stderr via init in store.go.
var messageWriter io.Writer
