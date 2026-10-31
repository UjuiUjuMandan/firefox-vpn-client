package vpnclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

func TestDefaultFirefoxUserAgent(t *testing.T) {
	t.Parallel()
	major, _, _ := strings.Cut(defaultFirefoxVersion, ".")
	want := "Mozilla/5.0 (X11; Linux x86_64; rv:" + major + ".0) Gecko/20100101 Firefox/" + defaultFirefoxVersion
	if got := defaultFirefoxUserAgent(); got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
}

func TestSetFxAUserAgent(t *testing.T) {
	previous := fxaUserAgentOverride.Load()
	t.Cleanup(func() { fxaUserAgentOverride.Store(previous) })
	if err := SetFxAUserAgent("  TestFirefox/1.0  "); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"   ", "Firefox\r\nInjected: value", "Firefox\n", "Firefox\t", "Firefox\x00", "Firefox\x7f", "火狐"} {
		if err := SetFxAUserAgent(invalid); err == nil {
			t.Errorf("accepted invalid User-Agent %q", invalid)
		}
		if got := fxaUserAgent(); got != "TestFirefox/1.0" {
			t.Fatalf("invalid override changed identity to %q", got)
		}
	}
	if err := SetFxAUserAgent(""); err != nil {
		t.Fatal(err)
	}
	if got := fxaUserAgent(); got != defaultFirefoxUserAgent() {
		t.Fatalf("reset identity = %q", got)
	}
}

type identityTestTransport func(*http.Request) (*http.Response, error)

func (f identityTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func identityTestResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func useIdentityTestClient(t *testing.T, transport http.RoundTripper, override string) {
	t.Helper()
	previousClient := controlPlaneHTTPClient
	previousUA := fxaUserAgentOverride.Load()
	t.Cleanup(func() {
		controlPlaneHTTPClient = previousClient
		fxaUserAgentOverride.Store(previousUA)
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	controlPlaneHTTPClient = &http.Client{Transport: transport, Jar: jar}
	if err := SetFxAUserAgent(override); err != nil {
		t.Fatal(err)
	}
}

func TestFxAEndpointsUseFirefoxIdentity(t *testing.T) {
	calls := 0
	transport := identityTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if got := req.UserAgent(); got != defaultFirefoxUserAgent() {
			t.Errorf("%s User-Agent = %q", req.URL.Path, got)
		}
		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		return identityTestResponse(req, 200, `{}`), nil
	})
	useIdentityTestClient(t, transport, "")
	ctx := context.Background()
	if _, err := fxaLogin(ctx, "user@example.invalid", "password"); err != nil {
		t.Fatal(err)
	}
	session := strings.Repeat("ab", 32)
	if err := fxaVerifySession(ctx, session, "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := fxaOAuthToken(ctx, session); err != nil {
		t.Fatal(err)
	}
	if _, err := fxaRefreshToken(ctx, "test-refresh-token"); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("requests = %d, want 4", calls)
	}
}

func TestFxAChallengeRetryKeepsIdentity(t *testing.T) {
	for _, override := range []string{"", "CustomFirefox/1.0"} {
		t.Run(override, func(t *testing.T) {
			want := override
			if want == "" {
				want = defaultFirefoxUserAgent()
			}
			apiCalls, postBacks, pats, pages, scripts := 0, 0, 0, 0, 0
			transport := identityTestTransport(func(req *http.Request) (*http.Response, error) {
				if got := req.UserAgent(); got != want {
					t.Errorf("%s%s User-Agent = %q, want %q", req.URL.Host, req.URL.Path, got, want)
				}
				if req.URL.Host == "api.accounts.firefox.com" {
					if req.URL.Path == "/" {
						return identityTestResponse(req, 200, "API"), nil
					}
					apiCalls++
					if apiCalls == 1 {
						return identityTestResponse(req, 406, ""), nil
					}
					if _, err := req.Cookie("_fs_ch_cp_test"); err != nil {
						t.Error("API retry missing solved challenge cookie")
					}
					return identityTestResponse(req, 200, `{"access_token":"new-access","expires_in":3600}`), nil
				}
				switch req.URL.Path {
				case "/":
					pages++
					if _, err := req.Cookie("_fs_ch_cp_test"); err == nil {
						return identityTestResponse(req, 200, "Accounts"), nil
					}
					return identityTestResponse(req, 200, "Client Challenge /_fs-ch-test"), nil
				case "/_fs-ch-test/script.js":
					scripts++
					hash := sha256.Sum256([]byte("baseXX"))
					script := fmt.Sprintf(`init([{"ty":"pat","data":{}},{"ty":"pow","data":{"base":"base","hash":"%x"}}], "challenge-token", "/_fs-ch-test");`, hash)
					return identityTestResponse(req, 200, script), nil
				case "/_fs-ch-test/pat":
					pats++
					return identityTestResponse(req, 401, ""), nil
				case "/_fs-ch-test/fst-post-back":
					postBacks++
					resp := identityTestResponse(req, 200, `{"status":"success"}`)
					resp.Header.Set("Set-Cookie", "_fs_ch_cp_test=solved; Domain=firefox.com; Path=/; Secure")
					return resp, nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", req.URL.Path)
				}
			})
			useIdentityTestClient(t, transport, override)
			token, err := fxaRefreshToken(context.Background(), "old-refresh")
			if err != nil {
				t.Fatal(err)
			}
			if token.AccessToken != "new-access" || token.RefreshToken != "old-refresh" {
				t.Fatal("unexpected tokens after challenge retry")
			}
			if apiCalls != 2 || postBacks != 1 || pats != 1 || pages != 2 || scripts != 1 {
				t.Fatalf("incomplete challenge path: api=%d postback=%d pat=%d page=%d script=%d", apiCalls, postBacks, pats, pages, scripts)
			}
			// The shared control-plane client must not turn this into a global UA override.
			req, _ := http.NewRequest(http.MethodGet, "https://vpn.mozilla.com/", nil)
			applyMozillaVPNHeaders(req)
			if req.UserAgent() != mozillaVPNUserAgent || req.Header.Get("Accept") != "application/json" {
				t.Fatal("Guardian/Remote Settings headers changed")
			}
		})
	}
}
