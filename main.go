package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	guardian := flag.String("guardian", guardianEndpointDefault, "Guardian API endpoint")
	skipServers := flag.Bool("no-servers", false, "Skip fetching the server list")
	login := flag.Bool("login", false, "Force fresh login (ignore saved tokens)")
	flag.Parse()

	var token *TokenResponse

	if !*login {
		saved, err := loadTokens()
		if err == nil && saved.RefreshToken != "" {
			fmt.Print("Refreshing token... ")
			token, err = fxaRefreshToken(saved.RefreshToken)
			if err != nil {
				fmt.Printf("failed: %v\n", err)
				fmt.Println("Falling back to login.")
				deleteTokens()
				token = nil
			} else {
				fmt.Println("OK")
			}
		}
	}

	if token == nil {
		reader := bufio.NewReader(os.Stdin)

		fmt.Println("=== Firefox VPN Proxy Client ===")
		fmt.Println()
		fmt.Print("Firefox Account email: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password := string(passwordBytes)

		fmt.Print("Logging in... ")
		loginResp, err := fxaLogin(email, password)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		fmt.Printf("  UID:      %s\n", loginResp.UID)
		fmt.Printf("  Verified: %v\n", loginResp.Verified)

		fmt.Print("Getting OAuth token... ")
		token, err = fxaOAuthToken(loginResp.SessionToken)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
	}

	if err := saveTokens(token); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save tokens: %v\n", err)
	} else {
		fmt.Printf("Tokens saved to %s\n", tokenFilePath())
	}

	fmt.Println()
	fmt.Println("=== OAuth Token ===")
	fmt.Printf("Access Token:  %s...%s\n", token.AccessToken[:min(10, len(token.AccessToken))], token.AccessToken[max(0, len(token.AccessToken)-10):])
	fmt.Printf("Token Type:    %s\n", token.TokenType)
	fmt.Printf("Scope:         %s\n", token.Scope)
	fmt.Printf("Expires In:    %d seconds\n", token.ExpiresIn)
	if token.RefreshToken != "" {
		fmt.Printf("Refresh Token: %s...%s\n", token.RefreshToken[:min(10, len(token.RefreshToken))], token.RefreshToken[max(0, len(token.RefreshToken)-10):])
	}

	fmt.Println()
	fmt.Println("=== User Info ===")
	ent, err := fetchUserInfo(*guardian, token.AccessToken)
	if err != nil {
		fmt.Printf("Warning: could not fetch user info: %v\n", err)
	} else {
		fmt.Printf("Subscribed:    %v\n", ent.Subscribed)
		fmt.Printf("UID:           %d\n", ent.UID)
		fmt.Printf("Max Bytes:     %s\n", ent.MaxBytes)
	}

	fmt.Println()
	fmt.Println("=== Proxy Pass ===")
	pass, err := fetchProxyPass(*guardian, token.AccessToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching proxy pass: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("JWT Token:     %s...%s\n", pass.RawToken[:min(20, len(pass.RawToken))], pass.RawToken[max(0, len(pass.RawToken)-20):])
	fmt.Printf("Subject:       %s\n", pass.Claims.Sub)
	fmt.Printf("Issuer:        %s\n", pass.Claims.Iss)
	fmt.Printf("Audience:      %s\n", pass.Claims.Aud)
	fmt.Printf("Not Before:    %s\n", pass.NotBefore().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Expires At:    %s\n", pass.ExpiresAt().Format("2006-01-02 15:04:05 UTC"))

	if pass.QuotaMax != "" {
		fmt.Println()
		fmt.Println("=== Usage Quota ===")
		fmt.Printf("Limit:         %s bytes\n", pass.QuotaMax)
		fmt.Printf("Remaining:     %s bytes\n", pass.QuotaLeft)
		fmt.Printf("Resets At:     %s\n", pass.QuotaReset)
	}

	var countries []Country
	if !*skipServers {
		fmt.Println()
		fmt.Println("=== Server List ===")
		var err error
		countries, err = fetchServerList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch server list: %v\n", err)
		} else if len(countries) == 0 {
			fmt.Println("No servers found in Remote Settings.")
		} else {
			printServerList(countries)
		}
	}

	proxyHost := "<PROXY_HOST:PORT>"
	for _, c := range countries {
		for _, city := range c.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				for _, proto := range srv.Protocols {
					if proto.Name == "connect" {
						proxyHost = fmt.Sprintf("%s:%d", proto.Host, proto.Port)
						goto found
					}
				}
			}
		}
	}
found:

	fmt.Println()
	fmt.Println("=== How to Connect ===")
	fmt.Println()
	fmt.Println("Example curl command (using first available CONNECT server):")
	fmt.Println()
	fmt.Printf("  curl -v --proxy https://%s \\\n", proxyHost)
	fmt.Printf("    --proxy-header \"Proxy-Authorization: Bearer %s\" \\\n", pass.RawToken)
	fmt.Println("    https://ifconfig.me")
	fmt.Println()
	fmt.Println("Full JWT token for scripting:")
	fmt.Println(pass.RawToken)
}
