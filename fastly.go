// Package vpnclient implements the Firefox VPN control plane client: FxA
// login and OAuth tokens, Guardian proxy passes, the Remote Settings server
// list, and the Fastly anti-bot challenge solver.
package vpnclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	fxaAPIHost = "https://api.accounts.firefox.com"
	fxaSiteURL = "https://accounts.firefox.com/"

	// fastlySolveTimeout bounds one full challenge-solving attempt. It is
	// deliberately longer than a single API call because solving involves
	// several sequential requests (page, script, challenge answer,
	// post-back, probe).
	fastlySolveTimeout = 60 * time.Second

	// maxPostBackRounds caps follow-up challenge rounds returned by
	// fst-post-back ({ch, tok} responses).
	maxPostBackRounds = 3

	// fastlySolverUserAgent mirrors the browser user agent the Fastly
	// challenge script expects.
	fastlySolverUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/126.0 Safari/537.36"

	// challengeBodyLimit caps one challenge post-back or PAT response body.
	challengeBodyLimit = 1 << 20

	// pageBodyLimit caps one challenge page or script response body.
	pageBodyLimit = 2 << 20

	// powSuffixLen is the length of the proof-of-work suffix brute-forced
	// by solvePow.
	powSuffixLen = 2

	// clientMetricsVersion is the schema version of the fabricated
	// browser-metrics payload.
	clientMetricsVersion = 2

	// truncateLimit bounds the response excerpt embedded in error messages.
	truncateLimit = 256
)

// powAlphabet is the character set the Fastly proof-of-work solver
// brute-forces; it mirrors the challenge script's own alphabet.
const powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	fastlyChallengePrefixRe = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
	fastlyInitCallRe        = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)

	// challengeSolveMu serializes solving attempts: two concurrent solvers
	// would race on the control plane client's cookie jar and on the
	// exit-IP-bound cookie.
	challengeSolveMu sync.Mutex //nolint:gochecknoglobals // package-level serialization primitive is idiomatic Go

	// errNoChallengePage signals that a host served regular content
	// instead of a Fastly challenge page.
	errNoChallengePage = errors.New("host did not serve a Fastly challenge page")

	// errChallengeNotAccepted signals that the solved cookie was rejected
	// on the probe request, typically because the exit IP rotated between
	// solving and probing.
	errChallengeNotAccepted = errors.New("challenge cookie not accepted on this exit IP")

	// errChallengePrefixNotFound signals that the challenge page did not
	// reference the expected /_fs-ch-* asset prefix.
	errChallengePrefixNotFound = errors.New("challenge asset prefix not found")

	// errChallengePostBackRejected signals a non-OK post-back response.
	errChallengePostBackRejected = errors.New("challenge post-back rejected")

	// errUnexpectedPostBack signals a post-back response without a new
	// challenge round or token.
	errUnexpectedPostBack = errors.New("unexpected post-back response")

	// errChallengeIncomplete signals that the post-back rounds were
	// exhausted without a success response.
	//nolint:staticcheck // ST1005: Fastly is a proper noun (anti-bot vendor)
	errChallengeIncomplete = errors.New("Fastly challenge did not complete")

	// errUnexpectedHTTPStatus signals a non-OK HTTP status from the
	// challenge edge.
	errUnexpectedHTTPStatus = errors.New("unexpected HTTP status")

	// errChallengeInitNotFound signals that the challenge script did not
	// contain the expected init(...) call.
	errChallengeInitNotFound = errors.New("challenge init call not found in script")

	// errEmptyChallengeList signals an init call with zero challenges.
	errEmptyChallengeList = errors.New("empty challenge list")

	// errPowUnsolved signals that no proof-of-work suffix matched the
	// target hash.
	errPowUnsolved = errors.New("no proof-of-work solution found")

	// errUnsupportedChallengeType signals a challenge type the solver
	// cannot handle automatically (for example captcha).
	errUnsupportedChallengeType = errors.New("unsupported Fastly challenge type (captcha cannot be solved automatically)")

	// errPATRejected signals a non-OK PAT endpoint response.
	errPATRejected = errors.New("PAT request returned an error status")

	// errEmptyPAT signals an empty auth token in an otherwise successful
	// PAT response.
	errEmptyPAT = errors.New("empty PAT auth token")

	// errNoCookiesIssued signals that the challenge completed but the
	// solver jar stayed empty.
	errNoCookiesIssued = errors.New("challenge completed but no cookies were issued")
)

type fastlyChallenge struct {
	Ty   string          `json:"ty"`
	Data json.RawMessage `json:"data"`
}

type fastlyPowData struct {
	Base    string `json:"base"`
	Expires string `json:"expires"`
	HMAC    string `json:"hmac"`
	Hash    string `json:"hash"`
}

type fastlyPostBack struct {
	Token string `json:"token"`
	Data  []any  `json:"data"`
}

type fastlyPostBackResponse struct {
	Status string            `json:"status"`
	Ch     []fastlyChallenge `json:"ch"`
	Tok    string            `json:"tok"`
}

// solveFastlyChallenge performs the Fastly client-challenge handshake and
// installs the resulting anti-bot cookie into the control plane client's
// cookie jar. The solver shares the control plane client's transport so that
// the request exits through the same proxy (and therefore the same exit IP)
// as the subsequent API call: the issued cookie is bound to the exit IP that
// solved the challenge.
func solveFastlyChallenge(ctx context.Context) error {
	challengeSolveMu.Lock()
	defer challengeSolveMu.Unlock()

	ctx, cancel := contextWithMinDeadline(ctx, fastlySolveTimeout)
	defer cancel()

	// Prefer the host that actually rejected the API request, but fall
	// back to the site host: the API host usually serves no challenge
	// page at all and the cookie it needs is issued with Domain=firefox.com.
	var lastErr error

	for _, base := range []string{fxaAPIHost, strings.TrimRight(fxaSiteURL, "/")} {
		err := solveChallengeOnHost(ctx, base)
		if err == nil {
			return nil
		}

		lastErr = err

		if errors.Is(err, errNoChallengePage) {
			continue
		}
	}

	if lastErr == nil {
		lastErr = errNoChallengePage
	}

	return lastErr
}

// solveChallengeOnHost runs the whole challenge flow against one host using
// a throw-away client with a fresh cookie jar: re-solving with a client that
// already holds a valid challenge cookie fails because Fastly then serves
// the real page instead of the challenge page. Splitting the flow would
// obscure the request order.
//
//nolint:gocognit,cyclop,funlen // sequential protocol flow (page, script, answer, post-back, probe)
func solveChallengeOnHost(ctx context.Context, base string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("creating solver cookie jar: %w", err)
	}

	client := &http.Client{
		Transport: controlPlaneHTTPClient.Transport,
		Jar:       jar,
		Timeout:   fastlySolveTimeout,
	}
	pageURL := base + "/"

	page, isChallenge, err := fetchChallengePage(ctx, client, pageURL)
	if err != nil {
		return err
	}

	if !isChallenge {
		return errNoChallengePage
	}

	prefix := fastlyChallengePrefixRe.FindString(page)
	if prefix == "" {
		return fmt.Errorf("%w on %s", errChallengePrefixNotFound, base)
	}

	script, err := fetchText(ctx, client, base+prefix+"/script.js?reload=true")
	if err != nil {
		return fmt.Errorf("fetching challenge script: %w", err)
	}

	challenges, token, err := parseChallengeInit(script)
	if err != nil {
		return err
	}

	for range maxPostBackRounds {
		answers := make([]any, 0, len(challenges))

		for _, ch := range challenges {
			answer, err := answerChallenge(ctx, client, base+prefix, token, ch)
			if err != nil {
				return err
			}

			answers = append(answers, answer)
		}

		postBack, err := json.Marshal(fastlyPostBack{Token: token, Data: answers})
		if err != nil {
			return fmt.Errorf("marshaling post-back payload: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			base+prefix+"/fst-post-back", strings.NewReader(string(postBack)))
		if err != nil {
			return fmt.Errorf("creating post-back request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", fastlySolverUserAgent)
		req.Header.Set("Origin", baseOrigin(base+prefix))

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("challenge post-back: %w", err)
		}

		data, readErr := io.ReadAll(io.LimitReader(resp.Body, challengeBodyLimit))
		_ = resp.Body.Close()

		if readErr != nil {
			return fmt.Errorf("reading post-back response: %w", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: HTTP %d: %s",
				errChallengePostBackRejected, resp.StatusCode, truncate(string(data)))
		}

		var pbResp fastlyPostBackResponse

		err = json.Unmarshal(data, &pbResp)
		if err != nil {
			return fmt.Errorf("parsing post-back response: %w", err)
		}

		if pbResp.Status == "success" {
			// Probe before installing the cookie: with rotating-exit
			// proxies the cookie may be bound to an IP the API call
			// will not reuse, and the probe catches that immediately.
			_, stillChallenged, err := fetchChallengePage(ctx, client, pageURL)
			if err != nil {
				return err
			} else if stillChallenged {
				return errChallengeNotAccepted
			}

			return installChallengeCookies(jar, pageURL)
		}

		if len(pbResp.Ch) == 0 || pbResp.Tok == "" {
			return fmt.Errorf("%w: %s", errUnexpectedPostBack, truncate(string(data)))
		}

		challenges, token = pbResp.Ch, pbResp.Tok
	}

	return fmt.Errorf("%w within %d rounds", errChallengeIncomplete, maxPostBackRounds)
}

// fetchChallengePage fetches pageURL and reports whether the response is a
// Fastly client-challenge page.
func fetchChallengePage(ctx context.Context, client *http.Client, pageURL string) (string, bool, error) {
	body, err := fetchText(ctx, client, pageURL)
	if err != nil {
		return "", false, err
	}

	isChallenge := strings.Contains(body, "/_fs-ch-") && strings.Contains(body, "Client Challenge")

	return body, isChallenge, nil
}

func fetchText(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating GET request for %s: %w", rawURL, err)
	}

	req.Header.Set("User-Agent", fastlySolverUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting %s: %w", rawURL, err)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, pageBodyLimit))
	_ = resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("reading response of %s: %w", rawURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %w: HTTP %d", rawURL, errUnexpectedHTTPStatus, resp.StatusCode)
	}

	return string(data), nil
}

// parseChallengeInit extracts the challenge list and the challenge token
// from the trailing init([...], "token", "prefix", ...) call in the script.
func parseChallengeInit(script string) ([]fastlyChallenge, string, error) {
	matches := fastlyInitCallRe.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 {
		return nil, "", errChallengeInitNotFound
	}

	initCall := matches[len(matches)-1]

	var challenges []fastlyChallenge

	err := json.Unmarshal([]byte(initCall[1]), &challenges)
	if err != nil {
		return nil, "", fmt.Errorf("parsing challenge list: %w", err)
	}

	if len(challenges) == 0 {
		return nil, "", errEmptyChallengeList
	}

	return challenges, initCall[2], nil
}

// answerChallenge produces the fst-post-back answer payload for one
// challenge task.
func answerChallenge(
	ctx context.Context,
	client *http.Client,
	prefixURL, token string,
	challenge fastlyChallenge,
) (any, error) {
	switch challenge.Ty {
	case "pow":
		var powData fastlyPowData

		err := json.Unmarshal(challenge.Data, &powData)
		if err != nil {
			return nil, fmt.Errorf("parsing pow challenge: %w", err)
		}

		answer, ok := solvePow(powData.Base, powData.Hash)
		if !ok {
			return nil, fmt.Errorf("%w for base %q", errPowUnsolved, powData.Base)
		}

		return map[string]any{
			"ty":      "pow",
			"base":    powData.Base,
			"answer":  answer,
			"hmac":    powData.HMAC,
			"expires": powData.Expires,
		}, nil
	case "pat":
		auth, err := fetchPAT(ctx, client, prefixURL, token)
		if err != nil {
			return nil, err
		}

		return map[string]any{"ty": "pat", "auth": auth}, nil
	case "clientmetrics":
		return clientMetricsAnswer(), nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedChallengeType, challenge.Ty)
	}
}

// solvePow brute-forces the two-character suffix the challenge script looks
// for: SHA256(base + suffix) must equal the target hash. The search space
// is 62*62, so this is instant.
func solvePow(base, targetHex string) (string, bool) {
	target, err := hex.DecodeString(targetHex)
	if err != nil || len(target) != sha256.Size {
		return "", false
	}

	buf := make([]byte, len(base)+powSuffixLen)
	copy(buf, base)

	for i := range len(powAlphabet) {
		buf[len(base)] = powAlphabet[i]
		for j := range len(powAlphabet) {
			buf[len(base)+1] = powAlphabet[j]

			sum := sha256.Sum256(buf)

			if bytes.Equal(sum[:], target) {
				return string(buf[len(base):]), true
			}
		}
	}

	return "", false
}

// fetchPAT requests the Private Access Token for a "pat" challenge. A 401
// with a PrivateToken header means the client cannot mint a PAT (a browser
// platform feature); the challenge script aborts in that case and posts
// back an empty auth, which makes Fastly fall back to solvable challenges.
func fetchPAT(ctx context.Context, client *http.Client, prefixURL, token string) (string, error) {
	patURL := prefixURL + "/pat?token=" + url.QueryEscape(token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, patURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating PAT request: %w", err)
	}

	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fastlySolverUserAgent)
	req.Header.Set("Origin", baseOrigin(prefixURL))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("PAT request: %w", err)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, challengeBodyLimit))
	_ = resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("reading PAT response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		// Aborted PAT (servers answer 401 or 400 depending on client
		// fingerprint): empty auth triggers the PoW fallback server-side.
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d: %s", errPATRejected, resp.StatusCode, truncate(string(data)))
	}

	var out struct {
		Auth string `json:"auth"`
	}

	err = json.Unmarshal(data, &out)
	if err != nil {
		return "", fmt.Errorf("parsing PAT response: %w", err)
	}

	if out.Auth == "" {
		return "", errEmptyPAT
	}

	return out.Auth, nil
}

// clientMetricsAnswer fabricates a benign browser-metrics payload; Mozilla's
// configuration currently issues only PAT/PoW challenges, so this path is a
// best-effort fallback.
func clientMetricsAnswer() map[string]any {
	return map[string]any{
		"ty":                   "clientmetrics",
		"webdriver":            false,
		"bot_detection_result": map[string]any{"bot_detected": false, "bot_kind": nil},
		"browser_metrics":      map[string]any{"client_data": "{}", "error_trace": nil},
		"detector_results":     map[string]any{},
		"v":                    clientMetricsVersion,
	}
}

// installChallengeCookies copies the cookies earned by the solver into the
// control plane client's jar so subsequent FxA API calls carry them. The
// cookie is issued with Domain=firefox.com, which covers
// api.accounts.firefox.com.
func installChallengeCookies(solverJar http.CookieJar, pageURL string) error {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return fmt.Errorf("parsing challenge page URL: %w", err)
	}

	cookies := solverJar.Cookies(parsed)
	if len(cookies) == 0 {
		return errNoCookiesIssued
	}

	if controlPlaneHTTPClient.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return fmt.Errorf("creating control plane cookie jar: %w", err)
		}

		controlPlaneHTTPClient.Jar = jar
	}

	apiURL, err := url.Parse(fxaAuthServer + "/")
	if err != nil {
		return fmt.Errorf("parsing API URL: %w", err)
	}

	controlPlaneHTTPClient.Jar.SetCookies(apiURL, cookies)

	parsed2, _ := url.Parse(fxaSiteURL)
	controlPlaneHTTPClient.Jar.SetCookies(parsed2, cookies)

	return nil
}

// contextWithMinDeadline returns a context with at least d of deadline left.
// When the parent already has a longer deadline it is returned unchanged;
// otherwise the deadline is extended while the parent's cancellation still
// propagates.
func contextWithMinDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) >= d {
		return ctx, func() {}
	}

	extended, cancel := context.WithTimeout(context.WithoutCancel(ctx), d)
	watcherDone := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-watcherDone:
		}
	}()

	return extended, func() {
		close(watcherDone)
		cancel()
	}
}

// truncate shortens s to the excerpt length used in error messages.
func truncate(s string) string {
	if len(s) <= truncateLimit {
		return s
	}

	return s[:truncateLimit] + "..."
}

// baseOrigin derives the Origin header value for challenge requests from a
// "/_fs-ch-..." prefixed URL.
func baseOrigin(prefixURL string) string {
	if idx := strings.Index(prefixURL, "/_fs-ch-"); idx > 0 {
		return prefixURL[:idx]
	}

	return prefixURL
}
