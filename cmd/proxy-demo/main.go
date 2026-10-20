// Package main implements the proxy-demo CLI: it logs in to Firefox
// Accounts, fetches a Guardian proxy pass, and exposes a local SOCKS5
// CONNECT proxy over upstream HTTP/2 or HTTP/3 VPN connections.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vpnclient "firefox-vpn-client"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

const (
	socksVersion5       = 0x05
	socksCmdConnect     = 0x01
	socksAtypIPv4       = 0x01
	socksAtypDomain     = 0x03
	socksAtypIPv6       = 0x04
	socksAuthNoAuth     = 0x00
	socksAuthNoAccept   = 0xff
	socksReplySuccess   = 0x00
	socksReplyFailure   = 0x01
	socksReplyNotAllow  = 0x02
	socksReplyNetUnrch  = 0x03
	socksReplyHostUnrch = 0x04
	socksReplyCmdUnsup  = 0x07
	socksReplyAtypUnsup = 0x08
)

const (
	proxyPassRenewLead            = 2 * time.Minute
	proxyPassRetryDelay           = 30 * time.Second
	proxyPassRenewTimeout         = 2 * time.Minute
	oauthRefreshLead              = 2 * time.Minute
	maxOpenTunnelRebuildRetries   = 3
	defaultHandshakeTimeout       = 10 * time.Second
	defaultIdleTimeout            = 0
	defaultMaxConnections         = 256
	defaultUpstreamConnections    = 1
	upstreamSessionRetryDelay     = 10 * time.Second
	apiProxyDialTimeout           = 20 * time.Second
	defaultTunnelWriteBufSize     = 1 << 20
	upstreamKeepAliveInterval     = 10 * time.Second
	upstreamKeepAlivePingTimeout  = 5 * time.Second
	copyBufferSize                = 64 * 1024
	halfCloseDrainTimeout         = 2 * time.Minute
	maxDistinctOpenTimeoutTargets = 3
	maxDistinctBadGatewayTargets  = 3
	defaultExitCheckTimeout       = 10 * time.Second
	maxExitCheckResponseSize      = 64 * 1024
	defaultExitCheckURL           = "https://www.cloudflare.com/cdn-cgi/trace"

	// defaultConnectTimeout is the default upstream dial and handshake
	// timeout selected by -timeout.
	defaultConnectTimeout = 20 * time.Second

	// acceptRetryInitialDelay is the first backoff delay used when the
	// SOCKS listener's Accept fails.
	acceptRetryInitialDelay = 5 * time.Millisecond

	// acceptRetryMaxDelay caps the Accept failure backoff.
	acceptRetryMaxDelay = time.Second

	// fileModeOwnerOnly and dirModeOwnerOnly are the permission masks
	// for the persisted state files.
	fileModeOwnerOnly = 0600
	dirModeOwnerOnly  = 0700

	// statusDirMode is the permission mask for the status file directory.
	statusDirMode = 0755

	// proxySelectionFailureThreshold is how many consecutive startup
	// failures clear a persisted proxy selection.
	proxySelectionFailureThreshold = 3

	// SOCKS protocol byte counts.
	socksGreetingLen   = 2
	socksRequestHeader = 4
	socksPortBytesLen  = 2
	socksReservedByte  = 0x00
	socksPortShift     = 8
	socksReplyFixedLen = 6

	// proxyCopyDirectionCount is the number of copy goroutines a tunnel
	// runs (one per direction).
	proxyCopyDirectionCount = 2

	// h2ReadIdleTimeout, h2PingTimeout, and h2WriteByteTimeout configure
	// the HTTP/2 keepalive transport.
	h2ReadIdleTimeout  = 30 * time.Second
	h2PingTimeout      = 15 * time.Second
	h2WriteByteTimeout = 30 * time.Second

	// connectErrorBodyLimit caps the CONNECT error body read for
	// diagnostics.
	connectErrorBodyLimit = 2048

	// QUIC tuning for the HTTP/3 upstream session.
	quicKeepAlivePeriod   = 30 * time.Second
	quicInitialPacketSize = 1200
	minQUICDialAttempt    = 3 * time.Second

	// unknownCountryLabel marks proxy metadata that is not known.
	unknownCountryLabel = "unknown"

	// jwtPreviewLen is the number of leading/trailing JWT characters shown
	// in the print-info output.
	jwtPreviewLen = 20

	// apiRequestTimeout bounds a single control plane API call (FxA,
	// Guardian, Remote Settings); the shared client adds its own safety
	// timeout on top, and FxA calls extend it while solving the Fastly
	// anti-bot challenge.
	apiRequestTimeout = 15 * time.Second

	// quotaCheckInterval is how often the token pool's remaining monthly
	// quota is polled so rotation happens as soon as a token is exhausted,
	// without waiting for the proxy pass itself to expire.
	quotaCheckInterval = 15 * time.Minute
)

var (
	errProxyHTTP2Unavailable = errors.New("proxy did not negotiate HTTP/2")
	errProxyHTTP3Unavailable = errors.New("proxy did not negotiate HTTP/3")
	errProxySessionUnhealthy = errors.New("upstream proxy session became unhealthy")
	errNoUsableProxySession  = errors.New("no usable upstream proxy session")
	errTunnelDeadline        = errors.New("deadlines are not supported for HTTP CONNECT tunnel streams")
	errTokenPoolExhausted    = errors.New("no session tokens left in the pool; " +
		"wait for the monthly quota reset or provide a new token file")

	errNilTunnelOpener       = errors.New("nil tunnel opener")
	errExitCheckURLInvalid   = errors.New("exit check URL must use HTTPS and include a host")
	errExitCheckBadStatus    = errors.New("exit verification endpoint returned an error status")
	errExitCheckBodyTooLarge = errors.New("exit verification response exceeds size limit")
	errExitCheckNoIP         = errors.New("exit verification response did not contain a valid IP address")
	errExitCheckNoCountry    = errors.New("exit verification response did not " +
		"contain a valid two-letter country code")
	errNoRefreshToken   = errors.New("no refresh token available")
	errNoSessionTokens  = errors.New("no session tokens found")
	errNoConnectProxies = errors.New("no CONNECT proxies available from server list or " +
		"persisted state; pass -country CODE or -proxy HOST:PORT")
	errNoProxyForCountry = errors.New("no CONNECT proxy found for country")
	errMultipleCountries = errors.New("multiple VPN countries are available; " +
		"pass -country CODE or -proxy HOST:PORT instead of selecting a random country")
	errEmptyProxyValue               = errors.New("empty proxy value")
	errMissingProxyHost              = errors.New("missing proxy host")
	errSOCKS5NoContextSupport        = errors.New("socks5 dialer does not support contexts")
	errUnsupportedProxyScheme        = errors.New("unsupported proxy scheme (supported: http, https, socks5, socks5h)")
	errSessionPoolSizeInvalid        = errors.New("upstream session pool size must be at least 1")
	errEmptySessionToken             = errors.New("empty proxy session token")
	errSessionTokenUpdateUnsupported = errors.New("upstream session does not support token update")
	errUnexpectedSOCKSVersion        = errors.New("unexpected SOCKS version")
	errNoSupportedAuthMethods        = errors.New("no supported SOCKS auth methods")
	errUnexpectedRequestVersion      = errors.New("unexpected request version")
	errUnsupportedSOCKSCommand       = errors.New("unsupported SOCKS command")
	errNoResolvedAddresses           = errors.New("no addresses resolved")
	errNoRefreshTokenForRenewal      = errors.New("no refresh token available for background renewal")
	// verboseLogs is the process-wide verbose flag set from -verbose.
	verboseLogs bool //nolint:gochecknoglobals // process-wide CLI flag state read from every log helper
	// logMu serializes log writes from all connection goroutines.
	logMu sync.Mutex //nolint:gochecknoglobals // package-level log serialization primitive
)

// copyBufferPool recycles tunnel copy buffers across connections.
var copyBufferPool = sync.Pool{ //nolint:gochecknoglobals // idiomatic package-level sync.Pool

	New: func() any {
		return new([copyBufferSize]byte)
	},
}

func logEventf(level, format string, args ...any) {
	message := fmt.Sprintf(format, args...)

	logMu.Lock()
	defer logMu.Unlock()

	fmt.Fprintf(os.Stderr, "%s %-5s %s\n", time.Now().Format(time.RFC3339), level, message)
}

func logDebugf(format string, args ...any) {
	if !verboseLogs {
		return
	}

	logEventf("DEBUG", format, args...)
}

func logInfof(format string, args ...any) {
	logEventf("INFO", format, args...)
}

func logWarnf(format string, args ...any) {
	logEventf("WARN", format, args...)
}

func logErrorf(format string, args ...any) {
	logEventf("ERROR", format, args...)
}

func logTarget(target string) string {
	if verboseLogs {
		return target
	}

	return "<redacted; use -verbose>"
}

func logErr(err error) string {
	if err == nil {
		return "<nil>"
	}

	if verboseLogs {
		return err.Error()
	}

	var connectErr *proxyConnectHTTPError
	if errors.As(err, &connectErr) {
		sanitized := *connectErr
		if sanitized.body != "" {
			sanitized.body = "<redacted; use -verbose>"
		}

		return sanitized.Error()
	}

	return err.Error()
}

func logAddr(addr net.Addr) string {
	if addr == nil {
		return "<unknown>"
	}

	return addr.String()
}

//nolint:gocognit,gocyclo,cyclop,funlen,maintidx // CLI entry point: sequential flag validation and startup
func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintln(out, "Usage of proxy-demo:")
		_, _ = fmt.Fprintln(out, "  proxy-demo [-country CODE | -proxy https://HOST:PORT] "+
			"[-listen 127.0.0.1:1080] [-h3] [-print-info]")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "This program logs in to Firefox Accounts, fetches a VPN proxy pass, and")
		_, _ = fmt.Fprintln(out, "exposes a local SOCKS5 CONNECT proxy over one or more upstream "+
			"HTTP/2 or HTTP/3 connections.")
		_, _ = fmt.Fprintln(out)

		flag.PrintDefaults()
	}

	apiProxyFlag := flag.String("api-proxy", "",
		"Optional HTTP/HTTPS/SOCKS5 proxy for Firefox Accounts, Guardian, and Remote Settings API requests")
	guardianFlag := flag.String("guardian", vpnclient.GuardianEndpointDefault, "Guardian API endpoint")
	listenFlag := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	loginFlag := flag.Bool("login", false, "Force fresh login (ignore saved refresh token)")
	sessionTokenFlag := flag.String("session-token", "",
		"Session token, or path to a .txt file with one token per line; "+
			"tokens rotate automatically when their monthly quota runs out")
	printInfoFlag := flag.Bool("print-info", false, "Print user info, quota info, and server list, then exit")
	proxyFlag := flag.String("proxy", "", "Exact upstream proxy URL or host:port; mutually exclusive with -country")
	countryFlag := flag.String("country", "", "Mozilla VPN location country code or name "+
		"used when selecting an upstream proxy")
	timeoutFlag := flag.Duration("timeout", defaultConnectTimeout, "Upstream dial and handshake timeout")
	handshakeTimeoutFlag := flag.Duration("handshake-timeout", defaultHandshakeTimeout,
		"Maximum time allowed for a client SOCKS5 handshake; 0 disables the limit")
	idleTimeoutFlag := flag.Duration("idle-timeout", defaultIdleTimeout,
		"Maximum idle time for an established tunnel; 0 disables the limit")
	maxConnsFlag := flag.Int("max-conns", defaultMaxConnections, "Maximum concurrent client "+
		"connections; 0 disables the limit")
	upstreamConnsFlag := flag.Int("upstream-conns", defaultUpstreamConnections,
		"Number of upstream proxy sessions; client IP affinity is used when the value is above 1")
	statusFileFlag := flag.String("status-file", "", "Write runtime health status JSON to this file; disabled when empty")
	proxyStateFileFlag := flag.String("proxy-state-file", "", "Persist the automatically selected upstream "+
		"proxy to this file; disabled when empty")
	verifyExitFlag := flag.Bool("verify-exit", true, "Verify the actual public exit IP and country "+
		"with a non-fatal HTTPS data-path probe")
	exitCheckURLFlag := flag.String("exit-check-url", defaultExitCheckURL,
		"HTTPS endpoint returning Cloudflare trace or JSON exit IP and country fields")
	exitCheckTimeoutFlag := flag.Duration("exit-check-timeout", defaultExitCheckTimeout, "Maximum duration of the "+
		"exit verification probe")
	useH3Flag := flag.Bool("h3", false,
		"Use HTTP/3 (QUIC/UDP) instead of HTTP/2 (TCP) for the upstream connection")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose per-connection logs, including CONNECT target hosts")

	flag.Parse()

	verboseLogs = *verboseFlag

	err := configureAPIProxy(strings.TrimSpace(*apiProxyFlag))
	if err != nil {
		logErrorf("invalid -api-proxy: %s", logErr(err))
		os.Exit(1)
	}

	if *upstreamConnsFlag < 1 {
		logErrorf("invalid -upstream-conns %d: must be at least 1", *upstreamConnsFlag)
		os.Exit(1)
	}

	if *idleTimeoutFlag < 0 {
		logErrorf("invalid -idle-timeout %s: must not be negative", idleTimeoutFlag.String())
		os.Exit(1)
	}

	if *verifyExitFlag && *exitCheckTimeoutFlag <= 0 {
		logErrorf("invalid -exit-check-timeout %s: must be positive when exit verification is enabled",
			exitCheckTimeoutFlag.String())
		os.Exit(1)
	}

	proxyFlagValue := strings.TrimSpace(*proxyFlag)

	countryFlagValue := strings.TrimSpace(*countryFlag)
	if proxyFlagValue != "" && countryFlagValue != "" {
		logErrorf("-proxy and -country are mutually exclusive")
		os.Exit(1)
	}

	proxyStateFile := strings.TrimSpace(*proxyStateFileFlag)

	var persistedProxy proxyCandidate

	hasPersistedProxy := false

	if proxyFlagValue == "" && proxyStateFile != "" {
		var persistedErr error

		persistedProxy, persistedErr = loadProxySelection(proxyStateFile)
		hasPersistedProxy = persistedErr == nil
	}

	needsCountryMatch := !hasPersistedProxy || !proxyCandidateMatchesCountry(persistedProxy, countryFlagValue)
	needServerList := *printInfoFlag || (proxyFlagValue == "" && needsCountryMatch)
	runtimeAuth, tokenSource, countries, tokenPool := prepareDemoInputs(
		*loginFlag,
		strings.TrimSpace(*sessionTokenFlag),
		needServerList,
	)

	var (
		selectedProxy     proxyCandidate
		selectedFromState bool
		selectionSource   string
		proxyURL          *url.URL
	)

	if !*printInfoFlag {
		selectedProxy, selectedFromState, err = resolveProxyWithStateAndCountry(
			proxyFlagValue, countryFlagValue, countries, proxyStateFile)
		if err != nil {
			logErrorf("selecting proxy failed: %v", err)
			os.Exit(1)
		}

		selectionSource = "single_available_location"

		switch {
		case proxyFlagValue != "":
			selectionSource = "configured_proxy"
		case selectedFromState:
			selectionSource = "persisted"
		case countryFlagValue != "":
			selectionSource = "configured_country"
		}

		proxyURL, err = normalizeProxyURL(selectedProxy.Addr)
		if err != nil {
			logErrorf("invalid proxy %q: %v", selectedProxy.Addr, err)
			os.Exit(1)
		}
	}

	initialAuth := runtimeAuth

	pass, runtimeAuth, err := acquireInitialPass(*guardianFlag, runtimeAuth, tokenPool)
	if err == nil && runtimeAuth != initialAuth {
		if tokenPool != nil {
			tokenSource = "session token pool rotation"
		} else {
			tokenSource = "refresh token after Guardian rejection"
		}
	}

	if err != nil {
		logErrorf("fetching proxy pass failed: %v", err)
		os.Exit(1)
	}

	logProxyPassTimeCorrection(pass)

	if *printInfoFlag {
		printRuntimeInfo(*guardianFlag, runtimeAuth.Token.AccessToken, pass, countries)

		return
	}

	sessionStart := time.Now()

	controller, err := newProxyController(proxyControllerConfig{
		Guardian:   *guardianFlag,
		ProxyURL:   proxyURL,
		Timeout:    *timeoutFlag,
		Auth:       runtimeAuth,
		Pass:       pass,
		UseH3:      *useH3Flag,
		Sessions:   *upstreamConnsFlag,
		StatusFile: strings.TrimSpace(*statusFileFlag),
		TokenPool:  tokenPool,
	})
	if err != nil {
		if selectedFromState && proxyStateFile != "" {
			failures, cleared, recordErr := recordProxySelectionFailure(proxyStateFile, selectedProxy)

			switch {
			case recordErr != nil:
				logWarnf("recording persisted proxy failure failed path=%s err=%s", proxyStateFile, logErr(recordErr))
			case cleared:
				logWarnf("persisted proxy failed repeatedly; selection "+
					"cleared for next restart proxy=%s failures=%d", selectedProxy.Addr, failures)
			default:
				logWarnf("persisted proxy failed to establish; retaining selection "+
					"until failure threshold proxy=%s failures=%d threshold=%d",
					selectedProxy.Addr, failures, proxySelectionFailureThreshold)
			}
		}

		switch {
		case errors.Is(err, errProxyHTTP2Unavailable):
			logErrorf("upstream proxy does not support HTTP/2; refusing to start " +
				"because this server must use a single upstream TCP connection")
		case errors.Is(err, errProxyHTTP3Unavailable):
			logErrorf("upstream proxy did not negotiate HTTP/3 (h3 ALPN); the server may not support QUIC")
		default:
			logErrorf("establishing upstream proxy session failed: %v", err)
		}

		os.Exit(1)
	}

	upstreamSessionEstablishLatency := time.Since(sessionStart).Round(time.Millisecond)

	if proxyFlagValue == "" && proxyStateFile != "" {
		err := saveProxySelection(proxyStateFile, selectedProxy)
		if err != nil {
			logWarnf("saving proxy selection failed path=%s err=%s", proxyStateFile, logErr(err))
		}
	}

	go controller.runRenewalLoop()

	if tokenPool != nil {
		go controller.runQuotaMonitorLoop(quotaCheckInterval)

		logInfof("token rotation enabled tokens=%d quota_check_interval=%s", tokenPool.size(), quotaCheckInterval)
	}

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp", *listenFlag)
	if err != nil {
		logErrorf("listening on %s failed: %v", *listenFlag, err)
		os.Exit(1)
	}

	defer func() { _ = listener.Close() }()
	defer func() { _ = controller.Close() }()

	logInfof("SOCKS5 proxy started listen=%s upstream=%s auth_source=%q proxy_pass_exp=%s "+
		"max_conns=%d upstream_conns=%d handshake_timeout=%s idle_timeout=%s connect_timeout=%s verbose=%v",
		listener.Addr().String(),
		selectedProxy.Addr,
		tokenSource,
		pass.ExpiresAt().Format(time.RFC3339),
		*maxConnsFlag,
		*upstreamConnsFlag,
		handshakeTimeoutFlag.String(),
		idleTimeoutFlag.String(),
		timeoutFlag.String(),
		verboseLogs,
	)

	transportLabel := "http2"
	if *useH3Flag {
		transportLabel = "http3"
	}

	logInfof("transport=%s mode=%s renewal=background", transportLabel, upstreamMode(*upstreamConnsFlag))

	logInfof("upstream selected configured_country=%q configured_country_code=%s configured_city=%q "+
		"configured_city_code=%s proxy=%s selection_source=%s upstream_session_establish_latency=%s",
		selectedProxy.CountryNameOrUnknown(),
		selectedProxy.CountryCodeOrUnknown(),
		selectedProxy.CityNameOrUnknown(),
		selectedProxy.CityCodeOrUnknown(),
		selectedProxy.Addr,
		selectionSource,
		upstreamSessionEstablishLatency,
	)

	if *verifyExitFlag {
		go logVerifiedExit(controller, strings.TrimSpace(*exitCheckURLFlag), *exitCheckTimeoutFlag, selectedProxy.CountryCode)
	}

	server := newSocksServer(controller, *handshakeTimeoutFlag, *idleTimeoutFlag, *maxConnsFlag)

	var acceptRetryDelay time.Duration

	for {
		conn, err := listener.Accept()
		if err != nil {
			if acceptRetryDelay == 0 {
				acceptRetryDelay = acceptRetryInitialDelay
			} else {
				acceptRetryDelay *= 2
			}

			if acceptRetryDelay > acceptRetryMaxDelay {
				acceptRetryDelay = time.Second
			}

			logWarnf("accept failed; retrying delay=%s err=%v", acceptRetryDelay, err)
			time.Sleep(acceptRetryDelay)

			continue
		}

		acceptRetryDelay = 0

		go server.handleConn(conn)
	}
}

type exitProbeResult struct {
	IP          string
	CountryCode string
	Latency     time.Duration
	ProbeHost   string
}

func logVerifiedExit(opener tunnelOpener, rawURL string, timeout time.Duration, configuredCountryCode string) {
	result, err := verifyExit(opener, rawURL, timeout)
	if err != nil {
		logWarnf("exit verification failed probe_host=%s timeout=%s err=%s", exitProbeHost(rawURL), timeout, logErr(err))

		return
	}

	logInfof("exit verified ip=%s country_code=%s data_path_probe_latency=%s probe_host=%s",
		result.IP,
		result.CountryCode,
		result.Latency.Round(time.Millisecond),
		result.ProbeHost,
	)

	if configuredCountryCode != "" && !strings.EqualFold(configuredCountryCode, result.CountryCode) {
		logWarnf("verified exit country differs from configured upstream "+
			"location configured_country_code=%s verified_country_code=%s",
			configuredCountryCode,
			result.CountryCode,
		)
	}
}

func exitProbeHost(rawURL string) string {
	probeURL, err := url.Parse(rawURL)
	if err != nil || probeURL.Hostname() == "" {
		return "<invalid>"
	}

	return probeURL.Hostname()
}

func verifyExit(opener tunnelOpener, rawURL string, timeout time.Duration) (exitProbeResult, error) {
	if opener == nil {
		return exitProbeResult{}, errNilTunnelOpener
	}

	probeURL, err := url.Parse(rawURL)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("parsing exit check URL: %w", err)
	}

	if !strings.EqualFold(probeURL.Scheme, "https") || probeURL.Hostname() == "" {
		return exitProbeResult{}, errExitCheckURLInvalid
	}

	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, _, authority string) (net.Conn, error) {
			return openTunnelContext(ctx, opener, authority)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: timeout}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("creating exit verification request: %w", err)
	}

	request.Header.Set("Accept", "text/plain, application/json")
	request.Header.Set("User-Agent", "firefox-vpn-client-exit-check/1")

	started := time.Now()

	response, err := client.Do(request)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("requesting exit verification endpoint: %w", err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return exitProbeResult{}, fmt.Errorf("%w: HTTP %d", errExitCheckBadStatus, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxExitCheckResponseSize+1))
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("reading exit verification response: %w", err)
	}

	if len(body) > maxExitCheckResponseSize {
		return exitProbeResult{}, fmt.Errorf("%w: %d bytes", errExitCheckBodyTooLarge, maxExitCheckResponseSize)
	}

	exitIP, countryCode, err := parseExitProbeResponse(body)
	if err != nil {
		return exitProbeResult{}, err
	}

	return exitProbeResult{
		IP:          exitIP,
		CountryCode: countryCode,
		Latency:     time.Since(started),
		ProbeHost:   probeURL.Hostname(),
	}, nil
}

func openTunnelContext(ctx context.Context, opener tunnelOpener, authority string) (net.Conn, error) {
	type tunnelResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan tunnelResult)

	go func() {
		conn, err := opener.OpenTunnel(authority)
		select {
		case resultCh <- tunnelResult{conn: conn, err: err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for tunnel: %w", ctx.Err())
	}
}

func parseExitProbeResponse(body []byte) (string, string, error) {
	fields := make(map[string]string)

	for line := range strings.SplitSeq(string(body), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}

	exitIP := firstNonEmpty(fields["ip"], fields["query"])

	countryCode := firstNonEmpty(fields["loc"], fields["country_code"], fields["countrycode"])
	if exitIP == "" || countryCode == "" {
		var payload map[string]any

		err := json.Unmarshal(body, &payload)
		if err == nil {
			exitIP = firstNonEmpty(exitIP, jsonString(payload, "ip"), jsonString(payload, "query"))
			countryCode = firstNonEmpty(countryCode, jsonString(payload, "country_code"), jsonString(payload, "countryCode"))
		}
	}

	exitIP = strings.TrimSpace(exitIP)
	if net.ParseIP(exitIP) == nil {
		return "", "", errExitCheckNoIP
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if len(countryCode) != 2 ||
		countryCode[0] < 'A' || countryCode[0] > 'Z' ||
		countryCode[1] < 'A' || countryCode[1] > 'Z' {
		return "", "", errExitCheckNoCountry
	}

	return exitIP, countryCode, nil
}

func jsonString(payload map[string]any, key string) string {
	value, _ := payload[key].(string)

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func fetchProxyPassCtx(guardian, accessToken string) (*vpnclient.ProxyPassInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	pass, err := vpnclient.FetchProxyPass(ctx, guardian, accessToken)

	cancel()

	if err != nil {
		return nil, fmt.Errorf("fetching proxy pass: %w", err)
	}

	return pass, nil
}

func refreshRuntimeAuth(auth *runtimeAuth) (*runtimeAuth, error) {
	if auth == nil || auth.Token == nil || auth.Token.RefreshToken == "" {
		return nil, errNoRefreshToken
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	token, err := vpnclient.FxaRefreshToken(ctx, auth.Token.RefreshToken)

	cancel()

	if err != nil {
		return nil, fmt.Errorf("refreshing OAuth token: %w", err)
	}

	err = vpnclient.SaveTokens(token)
	if err != nil {
		logWarnf("saving refreshed tokens failed: %v", err)
	}

	return &runtimeAuth{Token: token, ObtainedAt: time.Now()}, nil
}

//nolint:funlen // sequential token-source selection; complexity bounded by gocognit
func prepareDemoInputs(
	forceLogin bool,
	sessionToken string,
	needServerList bool,
) (*runtimeAuth, string, []vpnclient.Country, *sessionTokenPool) {
	var (
		token           *vpnclient.TokenResponse
		tokenSource     string
		tokenObtainedAt time.Time
		tokenPool       *sessionTokenPool
	)

	switch {
	case sessionToken != "" && isExistingFile(sessionToken):
		var err error

		tokenPool, err = loadSessionTokenPool(sessionToken)
		if err != nil {
			logErrorf("loading session token file failed: %v", err)
			os.Exit(1)
		}

		logInfof("loaded session tokens file=%s tokens=%d", sessionToken, tokenPool.size())

		if from := tokenPool.resumedIndex(); from > 0 {
			logInfof("resuming from session token %d/%d (saved state)", from, tokenPool.size())
		}

		auth, err := activateNextPoolToken(tokenPool)
		if err != nil {
			logErrorf("activating session token failed: %v", err)
			os.Exit(1)
		}

		token = auth.Token
		tokenObtainedAt = auth.ObtainedAt
		tokenSource = fmt.Sprintf("session-token file %s (%d tokens)", sessionToken, tokenPool.size())
	case sessionToken != "":
		fmt.Print("Using provided session token... ")

		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		newToken, err := vpnclient.FxaOAuthToken(ctx, sessionToken)

		cancel()

		if err != nil {
			fmt.Printf("failed: %v\n", err)
			os.Exit(1)
		}

		token = newToken

		fmt.Println("OK")

		tokenSource = "session-token flag"
		tokenObtainedAt = time.Now()
	default:
		token, tokenSource, tokenObtainedAt = obtainOAuthToken(forceLogin)
	}

	if tokenSource != "cached access token" {
		err := vpnclient.SaveTokens(token)
		if err != nil {
			logWarnf("saving tokens failed: %v", err)
		}
	}

	var (
		countries []vpnclient.Country
		err       error
	)

	if needServerList {
		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		countries, err = vpnclient.FetchServerList(ctx)

		cancel()

		if err != nil {
			logWarnf("fetching server list failed: %v", err)
		}
	}

	return &runtimeAuth{
		Token:      token,
		ObtainedAt: tokenObtainedAt,
	}, tokenSource, countries, tokenPool
}

// sessionTokenPool holds session tokens loaded from a text file and hands
// them out one by one as the previous token's monthly quota is exhausted.
type sessionTokenPool struct {
	mu      sync.Mutex
	tokens  []string
	nextIdx int

	statePath   string // persists activation progress next to the token file
	checksum    string // sha256 of the token file; state is discarded if it differs
	resumedFrom int    // 1-based position restored from the state file, 0 if none
}

// sessionPoolState records which token was active when the state was written.
type sessionPoolState struct {
	Checksum       string `json:"checksum"`
	ActivatedIndex int    `json:"activated_index"` // 1-based position of the last activated token
}

// loadSessionTokenPool reads one session token per line from path, skipping
// blank lines, '#' comments and duplicates.
func loadSessionTokenPool(path string) (*sessionTokenPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the user-provided token file
	if err != nil {
		return nil, fmt.Errorf("reading token file: %w", err)
	}

	var tokens []string

	seen := make(map[string]struct{})

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, dup := seen[line]; dup {
			continue
		}

		seen[line] = struct{}{}

		tokens = append(tokens, line)
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("%w in %s", errNoSessionTokens, path)
	}

	pool := &sessionTokenPool{
		mu:          sync.Mutex{},
		tokens:      tokens,
		nextIdx:     0,
		statePath:   stateFilePath(path),
		checksum:    sha256Hex(data),
		resumedFrom: 0,
	}
	pool.restoreState()

	return pool, nil
}

func stateFilePath(tokenFilePath string) string {
	dir := filepath.Dir(tokenFilePath)
	name := filepath.Base(tokenFilePath) + ".state"

	return filepath.Join(dir, name)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// restoreState resumes the pool from the persisted activation index when the
// token file is unchanged since the state was written.
func (p *sessionTokenPool) restoreState() {
	data, err := os.ReadFile(p.statePath)
	if err != nil {
		return
	}

	var state sessionPoolState

	err = json.Unmarshal(data, &state)
	if err != nil {
		return
	}

	if state.Checksum != p.checksum || state.ActivatedIndex < 1 || state.ActivatedIndex > len(p.tokens) {
		return
	}
	// Retry the saved token first: its quota may still have traffic left.
	p.nextIdx = state.ActivatedIndex - 1
	p.resumedFrom = state.ActivatedIndex
}

// saveState persists the 1-based position of the last activated token so a
// restart can resume without replaying already exhausted tokens. The write is
// atomic (temp file + rename) so a hard shutdown mid-write cannot corrupt
// the state file. Failures (e.g. read-only directory) are logged and
// ignored: state persistence must never interrupt the proxy.
func (p *sessionTokenPool) saveState(index int) {
	data, err := json.Marshal(sessionPoolState{Checksum: p.checksum, ActivatedIndex: index})
	if err != nil {
		return
	}

	tmpPath := p.statePath + ".tmp"

	err = os.WriteFile(tmpPath, data, fileModeOwnerOnly)
	if err != nil {
		logWarnf("saving token pool state failed path=%s err=%v", p.statePath, err)

		return
	}

	err = os.Rename(tmpPath, p.statePath)
	if err != nil {
		_ = os.Remove(tmpPath)

		logWarnf("saving token pool state failed path=%s err=%v", p.statePath, err)
	}
}

func (p *sessionTokenPool) resumedIndex() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.resumedFrom
}

// next returns the next unused token together with its 1-based position.
func (p *sessionTokenPool) next() (string, int, int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextIdx >= len(p.tokens) {
		return "", 0, len(p.tokens), false
	}

	token := p.tokens[p.nextIdx]
	p.nextIdx++

	return token, p.nextIdx, len(p.tokens), true
}

func (p *sessionTokenPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.tokens)
}

// activateNextPoolToken exchanges the next session token from the pool for
// OAuth tokens, skipping tokens that FxA rejects.
func activateNextPoolToken(pool *sessionTokenPool) (*runtimeAuth, error) {
	for {
		sessionToken, index, total, ok := pool.next()
		if !ok {
			return nil, errTokenPoolExhausted
		}

		fmt.Printf("Activating session token %d/%d... ", index, total)

		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		token, err := vpnclient.FxaOAuthToken(ctx, sessionToken)

		cancel()

		if err != nil {
			fmt.Printf("failed: %v\n", err)

			continue
		}

		fmt.Println("OK")
		pool.saveState(index)

		return &runtimeAuth{Token: token, ObtainedAt: time.Now()}, nil
	}
}

// isQuotaExhausted reports whether the proxy pass quota headers indicate
// that no monthly traffic is left.
func isQuotaExhausted(pass *vpnclient.ProxyPassInfo) bool {
	if pass == nil || pass.QuotaLeft == "" {
		return false
	}

	left, err := strconv.ParseInt(pass.QuotaLeft, 10, 64)
	if err != nil {
		return false
	}

	return left <= 0
}

func isExistingFile(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.Mode().IsRegular()
}

// acquireInitialPass fetches the first proxy pass. A Guardian token
// rejection (HTTP 401/403) is recovered from by refreshing the OAuth token
// and activating the account; when the token's monthly quota is exhausted
// (HTTP 429 or zero remaining) and a session token pool is configured, it
// rotates to the next token.
//
//nolint:gocognit,cyclop // token rotation state machine: each branch is a distinct recovery path
func acquireInitialPass(
	guardian string,
	auth *runtimeAuth,
	pool *sessionTokenPool,
) (*vpnclient.ProxyPassInfo, *runtimeAuth, error) {
	for {
		pass, err := fetchProxyPassCtx(guardian, auth.Token.AccessToken)
		if err == nil && !isQuotaExhausted(pass) {
			return pass, auth, nil
		}

		if errors.Is(err, vpnclient.ErrTokenInvalid) {
			logInfof("cached OAuth access was rejected by Guardian; refreshing token")

			refreshed, refreshErr := refreshRuntimeAuth(auth)
			if refreshErr == nil {
				auth = refreshed
				pass, err = fetchProxyPassCtx(guardian, auth.Token.AccessToken)
			} else {
				logWarnf("refreshing OAuth token after Guardian rejection failed: %v", refreshErr)
			}

			if errors.Is(err, vpnclient.ErrTokenInvalid) {
				logInfof("Guardian account is not activated for Firefox VPN proxy access; activating")

				ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
				_, activateErr := vpnclient.ActivateGuardian(ctx, guardian, auth.Token.AccessToken)

				cancel()

				if activateErr != nil {
					logWarnf("activating Guardian account failed: %v", activateErr)
				} else {
					logInfof("Guardian account activated")

					pass, err = fetchProxyPassCtx(guardian, auth.Token.AccessToken)
				}
			}

			if err == nil && !isQuotaExhausted(pass) {
				return pass, auth, nil
			}
		}

		if err != nil && !errors.Is(err, vpnclient.ErrQuotaExceeded) && !errors.Is(err, vpnclient.ErrTokenInvalid) {
			// Transient failure (network, server error): no point burning
			// through the pool.
			return nil, nil, err
		}

		if pool == nil {
			if err != nil {
				return nil, nil, err
			}

			return pass, auth, nil
		}

		if errors.Is(err, vpnclient.ErrTokenInvalid) {
			logWarnf("session token rejected by Guardian; switching to the next token")
		} else {
			logWarnf("session token quota exhausted; switching to the next token")
		}

		nextAuth, nextErr := activateNextPoolToken(pool)
		if nextErr != nil {
			if err != nil {
				return nil, nil, err
			}

			return nil, nil, nextErr
		}

		saveErr := vpnclient.SaveTokens(nextAuth.Token)
		if saveErr != nil {
			logWarnf("saving tokens failed: %v", saveErr)
		}

		auth = nextAuth
	}
}

func printRuntimeInfo(guardian, accessToken string, pass *vpnclient.ProxyPassInfo, countries []vpnclient.Country) {
	fmt.Println("=== User Info ===")

	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	ent, err := vpnclient.FetchUserInfo(ctx, guardian, accessToken)

	cancel()

	if err != nil {
		fmt.Printf("Warning: could not fetch user info: %v\n", err)
	} else {
		fmt.Printf("Subscribed:    %v\n", ent.Subscribed)
		fmt.Printf("UID:           %d\n", ent.UID)
		fmt.Printf("Max Bytes:     %s\n", ent.MaxBytes)
	}

	fmt.Println()
	fmt.Println("=== Proxy Pass ===")
	fmt.Printf("JWT Token:     %s...%s\n",
		pass.RawToken[:min(jwtPreviewLen, len(pass.RawToken))],
		pass.RawToken[max(0, len(pass.RawToken)-jwtPreviewLen):])
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

	fmt.Println()
	fmt.Println("=== Server List ===")

	if len(countries) == 0 {
		fmt.Println("No servers found in Remote Settings.")

		return
	}

	vpnclient.PrintServerList(countries)
}

func logProxyPassTimeCorrection(pass *vpnclient.ProxyPassInfo) {
	if pass == nil || pass.ClaimTimeCorrection() == 0 {
		return
	}

	logWarnf("proxy pass JWT claim time correction "+
		"applied offset=%s expires_at=%s", pass.ClaimTimeCorrection(), pass.ExpiresAt().Format(time.RFC3339))
}

func upstreamMode(sessions int) string {
	if sessions <= 1 {
		return "single-upstream-connection"
	}

	return fmt.Sprintf("upstream-session-pool size=%d affinity=client-ip failover", sessions)
}

func obtainOAuthToken(forceLogin bool) (*vpnclient.TokenResponse, string, time.Time) {
	if !forceLogin {
		saved, err := vpnclient.LoadTokens()
		if err == nil {
			if saved.AccessTokenValid() {
				fmt.Println("Using cached OAuth access token... OK")

				return &vpnclient.TokenResponse{
					AccessToken:  saved.AccessToken,
					RefreshToken: saved.RefreshToken,
					ExpiresIn:    saved.ExpiresIn,
					Scope:        saved.Scope,
					TokenType:    "bearer",
				}, "cached access token", saved.ObtainedAt
			}

			if saved.RefreshToken != "" {
				fmt.Print("Refreshing token... ")

				ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
				token, err := vpnclient.FxaRefreshToken(ctx, saved.RefreshToken)

				cancel()

				if err != nil {
					fmt.Printf("failed: %v\n", err)
					logWarnf("saved tokens were preserved; retry by restarting the program, or use -login to force a fresh login")
					os.Exit(1)
				}

				fmt.Println("OK")

				return token, "refresh token", time.Now()
			}
		}
	}

	email, password := promptCredentials()

	fmt.Print("Logging in... ")

	loginCtx, loginCancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	loginResp, err := vpnclient.FxaLogin(loginCtx, email, password)

	loginCancel()

	if err != nil {
		fmt.Printf("failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")

	if !loginResp.Verified {
		verifySessionInteractively(email, loginResp.SessionToken, loginResp.VerificationMethod)
	}

	fmt.Print("Getting OAuth token... ")

	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	token, err := vpnclient.FxaOAuthToken(tokenCtx, loginResp.SessionToken)

	tokenCancel()

	if err != nil {
		fmt.Printf("failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")

	return token, "fresh login", time.Now()
}

// verifySessionInteractively prompts for the confirmation code FxA sent to
// the account email at login time and retries until the session is verified.
func verifySessionInteractively(email, sessionToken, verificationMethod string) {
	reader := bufio.NewReader(os.Stdin)

	if verificationMethod == "email" {
		// Server fell back to the confirmation-link flow; there is no
		// code to enter.
		fmt.Printf("This sign-in must be confirmed: a confirmation link was sent to %s.\n", email)
		fmt.Print("Open the link from the email, then press Enter here to continue: ")

		_, err := reader.ReadString('\n')
		if err != nil {
			logErrorf("reading confirmation input failed: %v", err)
			os.Exit(1)
		}

		return
	}

	fmt.Printf("This sign-in must be confirmed: a verification code was sent to %s.\n", email)

	for {
		fmt.Print("Enter the verification code from the email: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			logErrorf("reading verification code failed: %v", err)
			os.Exit(1)
		}

		code := strings.TrimSpace(line)
		if code == "" {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		err = vpnclient.FxaVerifySession(ctx, sessionToken, code)

		cancel()

		if err == nil {
			fmt.Println("Session verified.")

			return
		}

		fmt.Printf("Verification failed: %v\n", err)
	}
}

func promptCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Firefox VPN Proxy Demo ===")
	fmt.Println()
	fmt.Print("Firefox Account email: ")

	email, _ := reader.ReadString('\n')

	fmt.Print("Password: ")

	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))

	fmt.Println()

	if err != nil {
		logErrorf("reading password failed: %v", err)
		os.Exit(1)
	}

	return strings.TrimSpace(email), string(passwordBytes)
}

type proxyCandidate struct {
	Addr        string
	CountryName string
	CountryCode string
	CityName    string
	CityCode    string
}

type proxySelectionState struct {
	Addr        string `json:"addr"`
	CountryName string `json:"country_name,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	CityName    string `json:"city_name,omitempty"`
	CityCode    string `json:"city_code,omitempty"`
	Failures    int    `json:"consecutive_failures,omitempty"`
}

func (p proxyCandidate) CountryNameOrUnknown() string {
	if p.CountryName == "" {
		return unknownCountryLabel
	}

	return p.CountryName
}

func (p proxyCandidate) CountryCodeOrUnknown() string {
	if p.CountryCode == "" {
		return unknownCountryLabel
	}

	return p.CountryCode
}

func (p proxyCandidate) CityNameOrUnknown() string {
	if p.CityName == "" {
		return unknownCountryLabel
	}

	return p.CityName
}

func (p proxyCandidate) CityCodeOrUnknown() string {
	if p.CityCode == "" {
		return unknownCountryLabel
	}

	return p.CityCode
}

func resolveProxy(proxyFlag string, countries []vpnclient.Country) (proxyCandidate, error) {
	candidate, _, err := resolveProxyWithStateAndCountry(proxyFlag, "", countries, "")

	return candidate, err
}

func resolveProxyWithState(
	proxyFlag string,
	countries []vpnclient.Country,
	stateFile string,
) (proxyCandidate, bool, error) {
	return resolveProxyWithStateAndCountry(proxyFlag, "", countries, stateFile)
}

func resolveProxyWithStateAndCountry(
	proxyFlag, countryFilter string,
	countries []vpnclient.Country,
	stateFile string,
) (proxyCandidate, bool, error) {
	if proxyFlag != "" {
		if matched, ok := findProxyCandidate(proxyFlag, countries); ok {
			matched.Addr = proxyFlag

			return matched, false, nil
		}

		return proxyCandidate{
			Addr:        proxyFlag,
			CountryName: "",
			CountryCode: "",
			CityName:    "",
			CityCode:    "",
		}, false, nil
	}

	if stateFile != "" {
		persisted, err := loadProxySelection(stateFile)
		if err == nil {
			if proxyCandidateMatchesCountry(persisted, countryFilter) {
				if matched, ok := findProxyCandidate(persisted.Addr, countries); ok {
					matched.Addr = persisted.Addr

					return matched, true, nil
				}

				if len(countries) == 0 {
					return persisted, true, nil
				}

				logWarnf("persisted proxy is no longer present in server list; selecting a replacement proxy=%s", persisted.Addr)
			} else if countryFilter != "" {
				logInfof("persisted proxy does not match configured country; selecting a replacement proxy=%s "+
					"persisted_country_code=%s configured_country=%q",
					persisted.Addr,
					persisted.CountryCodeOrUnknown(),
					countryFilter,
				)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			logWarnf("loading persisted proxy selection failed path=%s err=%s", stateFile, logErr(err))
		}
	}

	candidate, err := selectProxyCandidate(countries, countryFilter)
	if err != nil {
		return proxyCandidate{}, false, err
	}

	return candidate, false, nil
}

func selectProxyCandidate(countries []vpnclient.Country, countryFilter string) (proxyCandidate, error) {
	proxies := connectProxyCandidates(countries)
	if len(proxies) == 0 {
		return proxyCandidate{}, errNoConnectProxies
	}

	countryFilter = strings.TrimSpace(countryFilter)
	if countryFilter != "" {
		for _, candidate := range proxies {
			if proxyCandidateMatchesCountry(candidate, countryFilter) {
				return candidate, nil
			}
		}

		return proxyCandidate{}, fmt.Errorf("%w %q; available country codes: %s",
			errNoProxyForCountry, countryFilter, availableCountryCodes(proxies))
	}

	selectedCountryCode := ""

	for _, candidate := range proxies {
		code := strings.ToUpper(strings.TrimSpace(candidate.CountryCode))
		if code == "" {
			continue
		}

		if selectedCountryCode == "" {
			selectedCountryCode = code

			continue
		}

		if code != selectedCountryCode {
			return proxyCandidate{}, fmt.Errorf("%w (available: %s)",
				errMultipleCountries, availableCountryCodes(proxies))
		}
	}

	return proxies[0], nil
}

func proxyCandidateMatchesCountry(candidate proxyCandidate, countryFilter string) bool {
	countryFilter = strings.TrimSpace(countryFilter)
	if countryFilter == "" {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(candidate.CountryCode), countryFilter) ||
		strings.EqualFold(strings.TrimSpace(candidate.CountryName), countryFilter)
}

func availableCountryCodes(candidates []proxyCandidate) string {
	seen := make(map[string]struct{})
	codes := make([]string, 0)

	for _, candidate := range candidates {
		code := strings.ToUpper(strings.TrimSpace(candidate.CountryCode))
		if code == "" {
			continue
		}

		if _, ok := seen[code]; ok {
			continue
		}

		seen[code] = struct{}{}

		codes = append(codes, code)
	}

	if len(codes) == 0 {
		return unknownCountryLabel
	}

	return strings.Join(codes, ",")
}

func loadProxySelection(path string) (proxyCandidate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the -proxy-state-file flag value
	if err != nil {
		return proxyCandidate{}, fmt.Errorf("reading persisted proxy state: %w", err)
	}

	var state proxySelectionState

	err = json.Unmarshal(data, &state)
	if err != nil {
		return proxyCandidate{}, fmt.Errorf("parsing persisted proxy state: %w", err)
	}

	_, err = canonicalProxyAddr(state.Addr)
	if err != nil {
		return proxyCandidate{}, fmt.Errorf("invalid persisted proxy %q: %w", state.Addr, err)
	}

	return proxyCandidate{
		Addr:        state.Addr,
		CountryName: state.CountryName,
		CountryCode: state.CountryCode,
		CityName:    state.CityName,
		CityCode:    state.CityCode,
	}, nil
}

func saveProxySelection(path string, candidate proxyCandidate) error {
	if path == "" {
		return nil
	}

	_, err := canonicalProxyAddr(candidate.Addr)
	if err != nil {
		return err
	}

	return writeProxySelectionState(path, proxySelectionState{
		Addr:        candidate.Addr,
		CountryName: candidate.CountryName,
		CountryCode: candidate.CountryCode,
		CityName:    candidate.CityName,
		CityCode:    candidate.CityCode,
		Failures:    0,
	})
}

func recordProxySelectionFailure(path string, candidate proxyCandidate) (int, bool, error) {
	state := proxySelectionState{
		Addr:        candidate.Addr,
		CountryName: candidate.CountryName,
		CountryCode: candidate.CountryCode,
		CityName:    candidate.CityName,
		CityCode:    candidate.CityCode,
		Failures:    0,
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the -proxy-state-file flag value
	if err == nil {
		var existing proxySelectionState
		if json.Unmarshal(data, &existing) == nil {
			existingAddr, existingErr := canonicalProxyAddr(existing.Addr)

			candidateAddr, candidateErr := canonicalProxyAddr(candidate.Addr)
			if existingErr == nil && candidateErr == nil && existingAddr == candidateAddr {
				state = existing
			}
		}
	}

	state.Failures++
	if state.Failures >= proxySelectionFailureThreshold {
		err := os.Remove(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return state.Failures, false, fmt.Errorf("removing persisted proxy state: %w", err)
		}

		return state.Failures, true, nil
	}

	return state.Failures, false, writeProxySelectionState(path, state)
}

func writeProxySelectionState(path string, state proxySelectionState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling proxy selection state: %w", err)
	}

	data = append(data, '\n')

	dir := filepath.Dir(path)

	err = os.MkdirAll(dir, dirModeOwnerOnly)
	if err != nil {
		return fmt.Errorf("creating proxy state directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating proxy state temp file: %w", err)
	}

	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	err = tmp.Chmod(fileModeOwnerOnly)
	if err != nil {
		_ = tmp.Close()

		return fmt.Errorf("restricting proxy state temp file: %w", err)
	}

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()

		return fmt.Errorf("writing proxy state temp file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("closing proxy state temp file: %w", err)
	}

	err = os.Rename(tmpName, path)
	if err != nil {
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replacing proxy state file: %w", err)
		}

		retryErr := os.Rename(tmpName, path)
		if retryErr != nil {
			return fmt.Errorf("replacing proxy state file after retry: %w", retryErr)
		}
	}

	err = os.Chmod(path, fileModeOwnerOnly)
	if err != nil {
		return fmt.Errorf("restricting proxy state file: %w", err)
	}

	return nil
}

func findProxyCandidate(proxyFlag string, countries []vpnclient.Country) (proxyCandidate, bool) {
	target, err := canonicalProxyAddr(proxyFlag)
	if err != nil {
		return proxyCandidate{
			Addr:        "",
			CountryName: "",
			CountryCode: "",
			CityName:    "",
			CityCode:    "",
		}, false
	}

	for _, candidate := range connectProxyCandidates(countries) {
		candidateAddr, err := canonicalProxyAddr(candidate.Addr)
		if err != nil {
			continue
		}

		if strings.EqualFold(candidateAddr, target) {
			return candidate, true
		}
	}

	return proxyCandidate{
		Addr:        "",
		CountryName: "",
		CountryCode: "",
		CityName:    "",
		CityCode:    "",
	}, false
}

func canonicalProxyAddr(raw string) (string, error) {
	proxyURL, err := normalizeProxyURL(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalizing proxy address: %w", err)
	}

	host := proxyURL.Host
	if proxyURL.Port() == "" {
		host = net.JoinHostPort(proxyURL.Hostname(), "443")
	}

	return strings.ToLower(host), nil
}

func connectProxyHosts(countries []vpnclient.Country) []string {
	candidates := connectProxyCandidates(countries)

	proxies := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		proxies = append(proxies, candidate.Addr)
	}

	return proxies
}

func connectProxyCandidates(countries []vpnclient.Country) []proxyCandidate {
	var proxies []proxyCandidate

	for _, country := range countries {
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}

				if len(srv.Protocols) == 0 && srv.Hostname != "" && srv.Port > 0 {
					proxies = append(proxies, proxyCandidate{
						Addr:        fmt.Sprintf("%s:%d", srv.Hostname, srv.Port),
						CountryName: country.Name,
						CountryCode: country.Code,
						CityName:    city.Name,
						CityCode:    city.Code,
					})

					continue
				}

				for _, proto := range srv.Protocols {
					if proto.Name == "connect" && proto.Host != "" && proto.Port > 0 {
						proxies = append(proxies, proxyCandidate{
							Addr:        fmt.Sprintf("%s:%d", proto.Host, proto.Port),
							CountryName: country.Name,
							CountryCode: country.Code,
							CityName:    city.Name,
							CityCode:    city.Code,
						})
					}
				}
			}
		}
	}

	return proxies
}

func normalizeProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errEmptyProxyValue
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy URL: %w", err)
	}

	if parsed.Host == "" {
		return nil, errMissingProxyHost
	}

	return parsed, nil
}

// configureAPIProxy routes control plane requests through raw, which may be an
// http, https, socks5, or socks5h proxy URL. An empty value leaves the default
// direct transport in place. Only the Firefox Accounts, Guardian, and Remote
// Settings calls are affected; the SOCKS5 data path keeps talking to the
// upstream VPN proxy directly.
func configureAPIProxy(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing API proxy URL: %w", err)
	}

	if parsed.Host == "" {
		return errMissingProxyHost
	}

	dialer := &net.Dialer{Timeout: apiProxyDialTimeout}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	switch parsed.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
		transport.DialContext = dialer.DialContext
	case "socks5", "socks5h":
		var auth *proxy.Auth

		if parsed.User != nil {
			password, _ := parsed.User.Password()
			auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
		}

		socksDialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, dialer)
		if err != nil {
			return fmt.Errorf("creating socks5 dialer: %w", err)
		}

		contextDialer, ok := socksDialer.(proxy.ContextDialer)
		if !ok {
			return errSOCKS5NoContextSupport
		}

		transport.DialContext = contextDialer.DialContext
	default:
		return fmt.Errorf("%w: %q", errUnsupportedProxyScheme, parsed.Scheme)
	}

	vpnclient.SetControlPlaneTransport(transport)
	logInfof("control plane API requests routed through proxy=%s scheme=%s", parsed.Host, parsed.Scheme)

	return nil
}

type tunnelOpener interface {
	OpenTunnel(authority string) (net.Conn, error)
}

// clientAffinityTunnelOpener keeps a client's tunnels on one upstream session
// when the implementation can provide session affinity.
type clientAffinityTunnelOpener interface {
	OpenTunnelForClient(authority, clientKey string) (net.Conn, error)
}

type proxySessionTokenUpdater interface {
	UpdateToken(token string) error
}

// proxySessionLivenessChecker is implemented by sessions that can report
// whether their underlying connection is still usable, so a silently dead
// session is skipped before a client connection is bound to it.
type proxySessionLivenessChecker interface {
	IsAlive() bool
}

// isSessionAlive reports whether session can still carry new tunnels.
// Sessions that cannot answer are assumed alive, keeping the reactive
// rebuild path as the fallback.
func isSessionAlive(session proxySession) bool {
	if session == nil {
		return false
	}

	if checker, ok := session.(proxySessionLivenessChecker); ok {
		return checker.IsAlive()
	}

	return true
}

type sessionFailureTracker struct {
	mu                 sync.Mutex
	openTimeoutTargets map[string]struct{}
	badGatewayTargets  map[string]struct{}
}

func (t *sessionFailureTracker) observe(authority string, err error) error {
	if err == nil {
		t.mu.Lock()
		t.openTimeoutTargets = nil
		t.badGatewayTargets = nil
		t.mu.Unlock()

		return nil
	}

	var (
		timeoutErr *tunnelOpenTimeoutError
		connectErr *proxyConnectHTTPError
	)

	t.mu.Lock()
	defer t.mu.Unlock()

	switch {
	case errors.As(err, &timeoutErr):
		if t.openTimeoutTargets == nil {
			t.openTimeoutTargets = make(map[string]struct{})
		}

		t.openTimeoutTargets[authority] = struct{}{}

		t.badGatewayTargets = nil
		if len(t.openTimeoutTargets) >= maxDistinctOpenTimeoutTargets {
			return fmt.Errorf("%w: %w", errProxySessionUnhealthy, err)
		}
	case errors.As(err, &connectErr) && connectErr.statusCode == http.StatusBadGateway:
		if t.badGatewayTargets == nil {
			t.badGatewayTargets = make(map[string]struct{})
		}

		t.badGatewayTargets[authority] = struct{}{}

		t.openTimeoutTargets = nil
		if len(t.badGatewayTargets) >= maxDistinctBadGatewayTargets {
			return fmt.Errorf("%w: %w", errProxySessionUnhealthy, err)
		}
	default:
		t.openTimeoutTargets = nil
		t.badGatewayTargets = nil
	}

	return err
}

type proxySession interface {
	tunnelOpener
	Close() error
}

type pooledProxySession struct {
	mu      sync.Mutex
	session proxySession
	healthy bool
	retired bool
	refs    int
}

type proxySessionPool struct {
	create         func() (proxySession, error)
	setCreateToken func(string)
	sessions       []*pooledProxySession
	clientSlots    map[string]int
	next           atomic.Uint64
	tokenMu        sync.RWMutex
	currentToken   string

	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	closeOnce sync.Once
}

func newProxySessionPool(
	size int,
	create func() (proxySession, error),
	setCreateToken ...func(string),
) (*proxySessionPool, error) {
	if size < 1 {
		return nil, errSessionPoolSizeInvalid
	}

	pool := &proxySessionPool{
		create:         create,
		setCreateToken: nil,
		sessions:       make([]*pooledProxySession, size),
		clientSlots:    make(map[string]int),
		next:           atomic.Uint64{},
		tokenMu:        sync.RWMutex{},
		currentToken:   "",
		mu:             sync.Mutex{},
		closed:         false,
		done:           make(chan struct{}),
		closeOnce:      sync.Once{},
	}
	if len(setCreateToken) > 0 {
		pool.setCreateToken = setCreateToken[0]
	}

	successes := 0

	var firstErr error

	for slotIndex := range size {
		session, err := create()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}

			logWarnf("creating upstream session failed slot=%d size=%d err=%s", slotIndex+1, size, logErr(err))

			continue
		}

		pool.sessions[slotIndex] = newPooledProxySession(session)
		successes++
	}

	if successes == 0 {
		_ = pool.Close()

		return nil, fmt.Errorf("creating upstream session pool: %w", firstErr)
	}

	if successes < size {
		logWarnf("upstream proxy session pool partially established "+
			"available=%d desired=%d affinity=client-ip failover=enabled", successes, size)

		for i := range pool.sessions {
			if pool.sessions[i] == nil {
				go pool.replenishSlot(i)
			}
		}
	} else {
		logInfof("upstream proxy session pool established size=%d affinity=client-ip failover=enabled", successes)
	}

	return pool, nil
}

func newPooledProxySession(session proxySession) *pooledProxySession {
	return &pooledProxySession{
		mu:      sync.Mutex{},
		session: session,
		healthy: true,
		retired: false,
		refs:    0,
	}
}

func (p *proxySessionPool) OpenTunnel(authority string) (net.Conn, error) {
	return p.openTunnel(authority, "")
}

func (p *proxySessionPool) OpenTunnelForClient(authority, clientKey string) (net.Conn, error) {
	return p.openTunnel(authority, clientKey)
}

func (p *proxySessionPool) UpdateToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return errEmptySessionToken
	}

	if p == nil {
		return errNoUsableProxySession
	}

	p.tokenMu.Lock()
	p.currentToken = token
	p.tokenMu.Unlock()

	if p.setCreateToken != nil {
		p.setCreateToken(token)
	}

	p.mu.Lock()
	sessions := append([]*pooledProxySession(nil), p.sessions...)
	p.mu.Unlock()

	updated := 0

	for _, pooled := range sessions {
		if pooled == nil {
			continue
		}

		session, acquired := pooled.acquire()
		if !acquired {
			continue
		}

		updater, ok := session.(proxySessionTokenUpdater)
		if !ok {
			pooled.release()

			return errSessionTokenUpdateUnsupported
		}

		err := updater.UpdateToken(token)
		if err != nil {
			pooled.release()

			return fmt.Errorf("updating upstream session token: %w", err)
		}

		pooled.release()

		updated++
	}

	if updated == 0 {
		return errNoUsableProxySession
	}

	return nil
}

func (p *proxySessionPool) Close() error {
	if p == nil {
		return nil
	}

	var sessions []*pooledProxySession

	p.closeOnce.Do(func() {
		close(p.done)
		p.mu.Lock()
		p.closed = true

		sessions = append(sessions, p.sessions...)
		for slotIndex := range p.sessions {
			p.sessions[slotIndex] = nil
		}
		p.mu.Unlock()
	})

	var err error

	for _, pooled := range sessions {
		if pooled == nil {
			continue
		}

		closeErr := pooled.closeNow()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}

	return err
}

func (p *proxySessionPool) applyCurrentToken(session proxySession) error {
	p.tokenMu.RLock()
	token := p.currentToken
	p.tokenMu.RUnlock()

	if token == "" {
		return nil
	}

	updater, ok := session.(proxySessionTokenUpdater)
	if !ok {
		return errSessionTokenUpdateUnsupported
	}

	err := updater.UpdateToken(token)
	if err != nil {
		return fmt.Errorf("applying current token to upstream session: %w", err)
	}

	return nil
}

func (p *proxySessionPool) openTunnel(authority, clientKey string) (net.Conn, error) {
	if p == nil || len(p.sessions) == 0 {
		return nil, errNoUsableProxySession
	}

	start := p.nextSlot(clientKey)

	var lastErr error

	for attemptIndex := range len(p.sessions) {
		slot := (start + attemptIndex) % len(p.sessions)

		pooled := p.slot(slot)
		if pooled == nil {
			continue
		}

		session, ok := pooled.acquire()
		if !ok {
			// A slot the keepalive marked unhealthy stays skipped until it is
			// retired, so retire it here to trigger background replenishment.
			if pooled.needsRetire() {
				p.setClientFallback(clientKey, start, slot, (slot+1)%len(p.sessions))
				p.retireSlot(slot, pooled)
			}

			continue
		}

		conn, err := session.OpenTunnel(authority)
		if err == nil {
			p.rememberClientSlot(clientKey, start, slot)

			return &pooledTunnelConn{
				Conn:    conn,
				release: pooled.release,
				once:    sync.Once{},
			}, nil
		}

		pooled.release()

		lastErr = err

		if !shouldRebuildProxySession(err) {
			return nil, fmt.Errorf("opening upstream tunnel: %w", err)
		}

		p.setClientFallback(clientKey, start, slot, (slot+1)%len(p.sessions))
		p.retireSlot(slot, pooled)
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errNoUsableProxySession
}

func (p *proxySessionPool) nextSlot(clientKey string) int {
	if clientKey == "" {
		// The counter wraps around the pool size, so the conversion is
		// bounded by len(p.sessions).
		return int((p.next.Add(1) - 1) % uint64(len(p.sessions))) //nolint:gosec // G115: bounded by len(p.sessions)
	}

	p.mu.Lock()
	if slot, ok := p.clientSlots[clientKey]; ok {
		p.mu.Unlock()

		return slot
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(clientKey))
	// The hash is taken modulo the pool size, so the conversion is bounded.
	slot := int(h.Sum32() % uint32(len(p.sessions))) //nolint:gosec // G115: bounded by len(p.sessions)
	p.clientSlots[clientKey] = slot
	p.mu.Unlock()

	return slot
}

func (p *proxySessionPool) rememberClientSlot(clientKey string, initialSlot, actualSlot int) {
	if clientKey == "" || initialSlot == actualSlot {
		return
	}

	p.mu.Lock()

	currentSlot, ok := p.clientSlots[clientKey]
	if !p.closed && ok && (currentSlot == initialSlot || p.sessions[currentSlot] == nil) {
		p.clientSlots[clientKey] = actualSlot
	}
	p.mu.Unlock()
}

func (p *proxySessionPool) setClientFallback(clientKey string, initialSlot, failedSlot, fallbackSlot int) {
	if clientKey == "" {
		return
	}

	p.mu.Lock()

	currentSlot, ok := p.clientSlots[clientKey]
	if !p.closed && ok && (currentSlot == initialSlot || currentSlot == failedSlot || p.sessions[currentSlot] == nil) {
		p.clientSlots[clientKey] = fallbackSlot
	}
	p.mu.Unlock()
}

func (p *proxySessionPool) slot(slotIndex int) *pooledProxySession {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || slotIndex < 0 || slotIndex >= len(p.sessions) {
		return nil
	}

	return p.sessions[slotIndex]
}

func (p *proxySessionPool) retireSlot(slotIndex int, expected *pooledProxySession) {
	expected.retire()

	p.mu.Lock()
	if p.closed || slotIndex < 0 || slotIndex >= len(p.sessions) || p.sessions[slotIndex] != expected {
		p.mu.Unlock()

		return
	}

	p.sessions[slotIndex] = nil
	p.mu.Unlock()

	go p.replenishSlot(slotIndex)
}

func (p *proxySessionPool) replenishSlot(slotIndex int) {
	for {
		p.mu.Lock()
		if p.closed || slotIndex < 0 || slotIndex >= len(p.sessions) || p.sessions[slotIndex] != nil {
			p.mu.Unlock()

			return
		}
		p.mu.Unlock()

		session, err := p.create()
		if err != nil {
			logWarnf("replenishing upstream session failed slot=%d err=%s", slotIndex+1, logErr(err))

			if !p.waitOrClosed(upstreamSessionRetryDelay) {
				return
			}

			continue
		}

		err = p.applyCurrentToken(session)
		if err != nil {
			_ = session.Close()

			logWarnf("applying renewed token to replenished upstream session failed slot=%d err=%s", slotIndex+1, logErr(err))

			if !p.waitOrClosed(upstreamSessionRetryDelay) {
				return
			}

			continue
		}

		pooled := newPooledProxySession(session)

		p.mu.Lock()
		if p.closed || p.sessions[slotIndex] != nil {
			p.mu.Unlock()

			_ = pooled.closeNow()

			return
		}

		p.sessions[slotIndex] = pooled
		p.mu.Unlock()
		logInfof("upstream proxy session replenished slot=%d", slotIndex+1)

		return
	}
}

func (p *proxySessionPool) waitOrClosed(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-p.done:
		return false
	}
}

//nolint:ireturn // the pool hands out sessions of varying concrete types behind proxySession by design
func (p *pooledProxySession) acquire() (proxySession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.healthy || p.retired || p.session == nil {
		return nil, false
	}

	if !isSessionAlive(p.session) {
		// The keepalive already saw this connection die. Mark it unhealthy so
		// openTunnel retires the slot and replenishes it in the background.
		p.healthy = false

		return nil, false
	}

	p.refs++

	return p.session, true
}

// needsRetire reports whether this slot holds a session that is unusable but
// has not been retired yet, so the caller can start a replacement.
func (p *pooledProxySession) needsRetire() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return !p.retired && !p.healthy
}

func (p *pooledProxySession) release() {
	session := p.releaseLocked()
	if session != nil {
		_ = session.Close()
	}
}

//nolint:ireturn // the pool hands out sessions of varying concrete types behind proxySession by design
func (p *pooledProxySession) releaseLocked() proxySession {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.refs > 0 {
		p.refs--
	}

	if p.refs == 0 && p.retired && p.session != nil {
		session := p.session
		p.session = nil

		return session
	}

	return nil
}

func (p *pooledProxySession) retire() {
	p.mu.Lock()
	p.healthy = false
	p.retired = true
	shouldClose := p.refs == 0 && p.session != nil

	var session proxySession
	if shouldClose {
		session = p.session
		p.session = nil
	}
	p.mu.Unlock()

	if session != nil {
		_ = session.Close()
	}
}

func (p *pooledProxySession) closeNow() error {
	p.mu.Lock()
	session := p.session
	p.session = nil
	p.healthy = false
	p.retired = true
	p.mu.Unlock()

	if session == nil {
		return nil
	}

	closeErr := session.Close()
	if closeErr != nil {
		return fmt.Errorf("closing pooled upstream session: %w", closeErr)
	}

	return nil
}

type pooledTunnelConn struct {
	net.Conn

	release func()
	once    sync.Once
}

func (c *pooledTunnelConn) Close() error {
	var err error

	c.once.Do(func() {
		closeErr := c.Conn.Close()
		if closeErr != nil {
			err = fmt.Errorf("closing pooled tunnel connection: %w", closeErr)
		}

		if c.release != nil {
			c.release()
		}
	})

	return err
}

func (c *pooledTunnelConn) CloseRead() error {
	if closeReader, ok := c.Conn.(interface{ CloseRead() error }); ok {
		err := closeReader.CloseRead()
		if err != nil {
			return fmt.Errorf("half-closing pooled tunnel read side: %w", err)
		}
	}

	return nil
}

func (c *pooledTunnelConn) CloseWrite() error {
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		err := closeWriter.CloseWrite()
		if err != nil {
			return fmt.Errorf("half-closing pooled tunnel write side: %w", err)
		}
	}

	return nil
}

type runtimeAuth struct {
	Token      *vpnclient.TokenResponse
	ObtainedAt time.Time
}

func (a *runtimeAuth) accessTokenValid(now time.Time) bool {
	if a == nil || a.Token == nil || a.Token.AccessToken == "" {
		return false
	}

	expiry := a.ObtainedAt.Add(time.Duration(a.Token.ExpiresIn) * time.Second)

	return now.Before(expiry.Add(-oauthRefreshLead))
}

type socksServer struct {
	upstream         tunnelOpener
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	connSlots        chan struct{}
}

func newSocksServer(upstream tunnelOpener, handshakeTimeout, idleTimeout time.Duration, maxConns int) *socksServer {
	var slots chan struct{}
	if maxConns > 0 {
		slots = make(chan struct{}, maxConns)
	}

	return &socksServer{
		upstream:         upstream,
		handshakeTimeout: handshakeTimeout,
		idleTimeout:      idleTimeout,
		connSlots:        slots,
	}
}

func (s *socksServer) acquireConnSlot() bool {
	if s.connSlots == nil {
		return true
	}

	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *socksServer) releaseConnSlot() {
	if s.connSlots == nil {
		return
	}

	<-s.connSlots
}

func (s *socksServer) handleConn(conn net.Conn) {
	start := time.Now()

	clientAddr := logAddr(conn.RemoteAddr())
	if !s.acquireConnSlot() {
		logWarnf("client rejected: connection limit reached client=%s", clientAddr)

		_ = conn.Close()

		return
	}

	defer s.releaseConnSlot()
	defer func() { _ = conn.Close() }()

	logDebugf("client connected client=%s", clientAddr)

	if s.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	}

	target, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		logDebugf("SOCKS5 handshake failed client=%s reply=%d err=%v", clientAddr, replyCode, err)

		if replyCode != 0 {
			writeErr := writeSOCKSReply(conn, replyCode, nil)
			if writeErr != nil {
				logDebugf("SOCKS5 handshake failure reply failed client=%s reply=%d err=%v", clientAddr, replyCode, writeErr)
			}
		}

		return
	}

	if s.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	logDebugf("SOCKS5 CONNECT requested client=%s target=%s", clientAddr, logTarget(target))

	var upstreamConn net.Conn
	if affinityUpstream, ok := s.upstream.(clientAffinityTunnelOpener); ok {
		upstreamConn, err = affinityUpstream.OpenTunnelForClient(target, clientAffinityKey(conn.RemoteAddr()))
	} else {
		upstreamConn, err = s.upstream.OpenTunnel(target)
	}

	if err != nil {
		reply := mapUpstreamError(err)
		logWarnf("upstream tunnel open failed "+
			"client=%s target=%s reply=%d err=%s", clientAddr, logTarget(target), reply, logErr(err))

		writeErr := writeSOCKSReply(conn, reply, nil)
		if writeErr != nil {
			logDebugf("SOCKS5 upstream failure reply failed "+
				"client=%s target=%s reply=%d err=%v", clientAddr, logTarget(target), reply, writeErr)
		}

		return
	}

	defer func() { _ = upstreamConn.Close() }()

	err = writeSOCKSReply(conn, socksReplySuccess, conn.LocalAddr())
	if err != nil {
		logDebugf("SOCKS5 success reply failed client=%s target=%s err=%v", clientAddr, logTarget(target), err)

		return
	}

	logDebugf("upstream tunnel open succeeded client=%s target=%s", clientAddr, logTarget(target))
	proxyBidirectional(conn, upstreamConn, s.idleTimeout)
	logDebugf("client disconnected client=%s "+
		"target=%s duration=%s", clientAddr, logTarget(target), time.Since(start).Round(time.Millisecond))
}

func clientAffinityKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String()
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}

	return addr.String()
}

func handshakeSOCKS5(conn net.Conn) (string, byte, error) {
	header := make([]byte, socksGreetingLen)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return "", 0, fmt.Errorf("reading SOCKS greeting: %w", err)
	}

	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("%w %d", errUnexpectedSOCKSVersion, header[0])
	}

	methods := make([]byte, int(header[1]))

	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return "", 0, fmt.Errorf("reading SOCKS auth methods: %w", err)
	}

	method := byte(socksAuthNoAccept)

	if slices.Contains(methods, socksAuthNoAuth) {
		method = socksAuthNoAuth
	}

	_, err = conn.Write([]byte{socksVersion5, method})
	if err != nil {
		return "", 0, fmt.Errorf("writing SOCKS auth reply: %w", err)
	}

	if method == socksAuthNoAccept {
		return "", 0, errNoSupportedAuthMethods
	}

	reqHeader := make([]byte, socksRequestHeader)

	_, err = io.ReadFull(conn, reqHeader)
	if err != nil {
		return "", 0, fmt.Errorf("reading SOCKS request header: %w", err)
	}

	if reqHeader[0] != socksVersion5 {
		return "", socksReplyFailure, fmt.Errorf("%w %d", errUnexpectedRequestVersion, reqHeader[0])
	}

	if reqHeader[1] != socksCmdConnect {
		return "", socksReplyCmdUnsup, fmt.Errorf("%w %d", errUnsupportedSOCKSCommand, reqHeader[1])
	}

	host, err := readSOCKSAddr(conn, reqHeader[3])
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			return "", socksReplyAtypUnsup, err
		}

		return "", socksReplyFailure, fmt.Errorf("reading SOCKS target address: %w", err)
	}

	portBytes := make([]byte, socksPortBytesLen)

	_, err = io.ReadFull(conn, portBytes)
	if err != nil {
		return "", socksReplyFailure, fmt.Errorf("reading SOCKS target port: %w", err)
	}

	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), socksReplySuccess, nil
}

var errUnsupportedAddrType = errors.New("unsupported SOCKS address type")

func readSOCKSAddr(reader io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)

		_, err := io.ReadFull(reader, buf)
		if err != nil {
			return "", fmt.Errorf("reading SOCKS IPv4 address: %w", err)
		}

		return net.IP(buf).String(), nil
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)

		_, err := io.ReadFull(reader, buf)
		if err != nil {
			return "", fmt.Errorf("reading SOCKS IPv6 address: %w", err)
		}

		return net.IP(buf).String(), nil
	case socksAtypDomain:
		var size [1]byte

		_, err := io.ReadFull(reader, size[:])
		if err != nil {
			return "", fmt.Errorf("reading SOCKS domain length: %w", err)
		}

		buf := make([]byte, int(size[0]))

		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return "", fmt.Errorf("reading SOCKS domain: %w", err)
		}

		return string(buf), nil
	default:
		return "", errUnsupportedAddrType
	}
}

func writeSOCKSReply(writer io.Writer, replyCode byte, addr net.Addr) error {
	host := "0.0.0.0"
	port := 0

	if addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			host = tcpAddr.IP.String()
			port = tcpAddr.Port
		}
	}

	parsedIP := net.ParseIP(host)
	atyp := byte(socksAtypIPv4)

	addrBytes := []byte{0, 0, 0, 0}
	if parsedIP != nil && parsedIP.To4() != nil {
		addrBytes = parsedIP.To4()
	} else if parsedIP != nil && parsedIP.To16() != nil {
		atyp = socksAtypIPv6
		addrBytes = parsedIP.To16()
	}

	reply := make([]byte, 0, socksReplyFixedLen+len(addrBytes))
	reply = append(reply, socksVersion5, replyCode, socksReservedByte, atyp)
	reply = append(reply, addrBytes...)
	reply = append(reply, byte(port>>socksPortShift), byte(port))

	_, err := writer.Write(reply)
	if err != nil {
		return fmt.Errorf("writing SOCKS reply: %w", err)
	}

	return nil
}

func mapUpstreamError(err error) byte {
	if errors.Is(err, errNoUsableProxySession) {
		return socksReplyHostUnrch
	}

	if errors.Is(err, errUnsupportedAddrType) {
		return socksReplyAtypUnsup
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socksReplyHostUnrch
	}

	return socksReplyFailure
}

type tunnelOpenTimeoutError struct {
	timeout time.Duration
}

func (e *tunnelOpenTimeoutError) Error() string {
	return fmt.Sprintf("proxy CONNECT timed out after %s", e.timeout)
}

func (e *tunnelOpenTimeoutError) Timeout() bool {
	return true
}

func (e *tunnelOpenTimeoutError) Temporary() bool {
	return true
}

type proxyConnectHTTPError struct {
	statusCode int
	status     string
	body       string
}

func (e *proxyConnectHTTPError) Error() string {
	if e.body == "" {
		return "proxy CONNECT failed: " + e.status
	}

	return fmt.Sprintf("proxy CONNECT failed: %s: %s", e.status, e.body)
}

func shouldRebuildProxySession(err error) bool {
	if errors.Is(err, errProxySessionUnhealthy) {
		return true
	}

	var connectErr *proxyConnectHTTPError
	if errors.As(err, &connectErr) {
		switch connectErr.statusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired:
			return true
		default:
			return false
		}
	}

	var timeoutErr *tunnelOpenTimeoutError

	return !errors.As(err, &timeoutErr)
}

type roundTripResult struct {
	resp *http.Response
	err  error
}

func roundTripWithOpenTimeout(
	timeout time.Duration,
	roundTrip func(context.Context) (*http.Response, error),
) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout <= 0 {
		resp, err := roundTrip(ctx)
		if err != nil {
			cancel()

			return nil, nil, err
		}

		return resp, cancel, nil
	}

	resultCh := make(chan roundTripResult, 1)

	go func() {
		resp, err := roundTrip(ctx) //nolint:bodyclose // the timeout cleanup goroutine closes the body when the deadline wins
		resultCh <- roundTripResult{resp: resp, err: err}
	}()

	timer := time.NewTimer(timeout)
	select {
	case result := <-resultCh:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		if result.err != nil {
			cancel()

			return nil, nil, result.err
		}

		return result.resp, cancel, nil
	case <-timer.C:
		cancel()

		go func() {
			cleanupTimer := time.NewTimer(timeout)
			defer cleanupTimer.Stop()

			select {
			case result := <-resultCh:
				if result.resp != nil && result.resp.Body != nil {
					_ = result.resp.Body.Close()
				}
			case <-cleanupTimer.C:
			}
		}()

		return nil, nil, &tunnelOpenTimeoutError{timeout: timeout}
	}
}

func proxyBidirectional(clientConn, upstreamConn net.Conn, idleTimeout time.Duration) {
	var activity func()

	done := make(chan struct{})

	if idleTimeout > 0 {
		activityCh := make(chan struct{}, 1)
		activity = func() {
			select {
			case activityCh <- struct{}{}:
			default:
			}
		}

		go closeIdleConns(clientConn, upstreamConn, idleTimeout, activityCh, done)
	} else {
		activity = func() {}
	}

	results := make(chan error, proxyCopyDirectionCount)

	go func() {
		err := copyConn(upstreamConn, clientConn, activity)
		if err == nil {
			closeWrite(upstreamConn)
		}

		results <- err
	}()

	go func() {
		err := copyConn(clientConn, upstreamConn, activity)
		if err == nil {
			closeWrite(clientConn)
		}

		results <- err
	}()

	firstErr := <-results
	if firstErr != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}

	var secondErr error

	if firstErr == nil {
		drainTimer := time.NewTimer(halfCloseDrainTimeout)
		select {
		case secondErr = <-results:
			if !drainTimer.Stop() {
				<-drainTimer.C
			}
		case <-drainTimer.C:
			logDebugf("closing half-closed tunnel after drain timeout=%s", halfCloseDrainTimeout)

			_ = clientConn.Close()
			_ = upstreamConn.Close()
			secondErr = <-results
		}
	} else {
		secondErr = <-results
	}

	if secondErr != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}

	close(done)
}

func closeIdleConns(
	clientConn, upstreamConn net.Conn,
	idleTimeout time.Duration,
	activity <-chan struct{},
	done <-chan struct{},
) {
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	for {
		select {
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			timer.Reset(idleTimeout)
		case <-timer.C:
			_ = clientConn.Close()
			_ = upstreamConn.Close()

			return
		case <-done:
			return
		}
	}
}

func copyConn(dst, src net.Conn, activity func()) error {
	bufArray := copyBufferPool.Get().(*[copyBufferSize]byte) //nolint:forcetypeassert // pool New always returns this type
	defer copyBufferPool.Put(bufArray)

	buf := bufArray[:]

	for {
		readCount, readErr := src.Read(buf)
		if readCount > 0 {
			activity()

			writeCount, writeErr := dst.Write(buf[:readCount])
			if writeCount > 0 {
				activity()
			}

			if writeErr != nil {
				return fmt.Errorf("writing to tunnel peer: %w", writeErr)
			}

			if writeCount != readCount {
				return io.ErrShortWrite
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}

			return fmt.Errorf("reading from tunnel peer: %w", readErr)
		}
	}
}

func closeWrite(conn net.Conn) {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
}

type h2ProxySession struct {
	raw       *tls.Conn
	cc        *http2.ClientConn
	proxyHost string
	token     string
	timeout   time.Duration
	tokenMu   sync.RWMutex
	health    sessionFailureTracker
	closeOnce sync.Once
	closeErr  error

	// alive is cleared once a keepalive PING fails or the session is closed,
	// so the pool can skip it before binding a client connection to it.
	alive atomic.Bool
	// stopKeepAlive stops the keepalive goroutine on Close.
	stopKeepAlive context.CancelFunc
}

func newH2ProxySession(proxyURL *url.URL, token string, timeout time.Duration) (*h2ProxySession, error) {
	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyHost = proxyURL.Hostname() + ":443"
	}

	dialer := &net.Dialer{Timeout: timeout}

	proxyTLSCfg := &tls.Config{
		ServerName: proxyURL.Hostname(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}

	// The Dialer alternative returns net.Conn; the concrete *tls.Conn is required below.
	proxyTLS, err := tls.DialWithDialer(dialer, "tcp", proxyHost, proxyTLSCfg) //nolint:noctx // loses *tls.Conn
	if err != nil {
		return nil, fmt.Errorf("dialing upstream proxy TLS: %w", err)
	}

	if proxyTLS.ConnectionState().NegotiatedProtocol != "h2" {
		_ = proxyTLS.Close()

		return nil, errProxyHTTP2Unavailable
	}

	transport := &http2.Transport{
		ReadIdleTimeout:  h2ReadIdleTimeout,
		PingTimeout:      h2PingTimeout,
		WriteByteTimeout: h2WriteByteTimeout,
	}

	clientConn, err := transport.NewClientConn(proxyTLS)
	if err != nil {
		_ = proxyTLS.Close()

		return nil, fmt.Errorf("negotiating upstream HTTP/2 connection: %w", err)
	}

	logInfof("upstream HTTP/2 session established proxy=%s", proxyHost)

	ctx, cancel := context.WithCancel(context.Background())
	session := &h2ProxySession{
		raw:           proxyTLS,
		cc:            clientConn,
		proxyHost:     proxyHost,
		token:         token,
		timeout:       timeout,
		tokenMu:       sync.RWMutex{},
		health:        sessionFailureTracker{mu: sync.Mutex{}, openTimeoutTargets: nil, badGatewayTargets: nil},
		closeOnce:     sync.Once{},
		closeErr:      nil,
		alive:         atomic.Bool{},
		stopKeepAlive: cancel,
	}

	session.alive.Store(true)
	go session.runKeepAlive(ctx)

	return session, nil
}

// IsAlive reports whether this session can still carry new tunnels.
func (s *h2ProxySession) IsAlive() bool {
	if !s.alive.Load() {
		return false
	}

	return s.cc.CanTakeNewRequest()
}

//nolint:dupl // mirrored h3 implementation below; the two transports are deliberately parallel
func (s *h2ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	reqBody := newTunnelWriteBuffer(defaultTunnelWriteBufSize)

	resp, cancel, err := roundTripWithOpenTimeout(s.timeout, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+authority, reqBody)
		if err != nil {
			return nil, fmt.Errorf("creating h2 CONNECT request: %w", err)
		}

		req.Host = authority
		req.URL.Host = s.proxyHost
		req.Header.Set("Proxy-Authorization", "Bearer "+s.bearerToken())

		return s.cc.RoundTrip(req)
	})
	if err != nil {
		reqBody.failRead(io.ErrClosedPipe)

		return nil, s.health.observe(authority, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cancel()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, connectErrorBodyLimit))
		_ = resp.Body.Close()

		reqBody.failRead(io.ErrClosedPipe)

		return nil, s.health.observe(authority, &proxyConnectHTTPError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
			body:       strings.TrimSpace(string(body)),
		})
	}

	_ = s.health.observe(authority, nil)

	return &tunnelConn{
		reader:    resp.Body,
		writer:    reqBody,
		reqBody:   reqBody,
		name:      "h2-connect-stream",
		cancel:    cancel,
		closeOnce: sync.Once{},
		readOnce:  sync.Once{},
		writeOnce: sync.Once{},
		closeErr:  nil,
		readErr:   nil,
		writeErr:  nil,
	}, nil
}

func (s *h2ProxySession) UpdateToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return errEmptySessionToken
	}

	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()

	return nil
}

func (s *h2ProxySession) Close() error {
	s.closeOnce.Do(func() {
		s.alive.Store(false)

		if s.stopKeepAlive != nil {
			s.stopKeepAlive()
		}

		if s.cc != nil {
			s.closeErr = s.cc.Close()
		}

		if s.raw != nil {
			closeErr := s.raw.Close()
			if s.closeErr == nil {
				s.closeErr = closeErr
			}
		}
	})

	return s.closeErr
}

// runKeepAlive pings the upstream connection periodically so a silently
// dropped session is noticed while idle, rather than when a client next tries
// to open a tunnel through it.
func (s *h2ProxySession) runKeepAlive(ctx context.Context) {
	ticker := time.NewTicker(upstreamKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, upstreamKeepAlivePingTimeout)
			err := s.cc.Ping(pingCtx)

			cancel()

			if err == nil {
				continue
			}

			if ctx.Err() != nil {
				return
			}

			s.alive.Store(false)
			logWarnf("upstream HTTP/2 keepalive failed proxy=%s err=%s", s.proxyHost, logErr(err))

			return
		}
	}
}

func (s *h2ProxySession) bearerToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()

	return s.token
}

// h3ProxySession holds a single QUIC connection used for HTTP/3 CONNECT tunnels.
type h3ProxySession struct {
	conn      *quic.Conn
	udpConn   *net.UDPConn
	rt        *http3.Transport
	proxyHost string
	token     string
	timeout   time.Duration
	tokenMu   sync.RWMutex
	health    sessionFailureTracker
	closeOnce sync.Once
	closeErr  error
}

//nolint:funlen // sequential QUIC resolve-dial-negotiate flow with documented tuning comments
func newH3ProxySession(proxyURL *url.URL, token string, timeout time.Duration) (*h3ProxySession, error) {
	host := proxyURL.Hostname()

	portStr := proxyURL.Port()
	if portStr == "" {
		portStr = "443"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy port %q: %w", portStr, err)
	}

	proxyHost := net.JoinHostPort(host, portStr)

	ctx := context.Background()

	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("%w for %s", errNoResolvedAddresses, host)
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	quicCfg := &quic.Config{
		KeepAlivePeriod: quicKeepAlivePeriod,
		// Default InitialPacketSize (1280) is the QUIC payload size;
		// once IP/UDP headers are added it exceeds low-MTU links so every
		// initial packet gets dropped and the handshake times out with no
		// QUIC traffic visible on the wire.
		// Start below the RFC 8899 floor so the handshake succeeds on any
		// path; PMTU discovery grows it back up.
		InitialPacketSize: quicInitialPacketSize,
	}

	var perAttempt time.Duration
	if timeout > 0 {
		perAttempt = max(timeout/time.Duration(len(ips)), minQUICDialAttempt)
	}

	var (
		conn    *quic.Conn
		udpConn *net.UDPConn
		lastErr error
	)

	for _, resolvedIP := range ips {
		udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			lastErr = err

			continue
		}

		udpAddr := &net.UDPAddr{IP: resolvedIP.AsSlice(), Port: port, Zone: resolvedIP.Zone()}
		attemptCtx := ctx

		attemptCancel := func() {}
		if perAttempt > 0 {
			attemptCtx, attemptCancel = context.WithTimeout(ctx, perAttempt)
		}

		quicConn, err := quic.Dial(attemptCtx, udpListener, udpAddr, tlsCfg, quicCfg)

		attemptCancel()

		if err != nil {
			_ = udpListener.Close()
			lastErr = fmt.Errorf("dial %s: %w", udpAddr, err)

			continue
		}

		conn = quicConn
		udpConn = udpListener

		break
	}

	if conn == nil {
		return nil, lastErr
	}

	if conn.ConnectionState().TLS.NegotiatedProtocol != "h3" {
		_ = conn.CloseWithError(0, "")
		_ = udpConn.Close()

		return nil, errProxyHTTP3Unavailable
	}

	logInfof("upstream HTTP/3 session established proxy=%s remote=%s", proxyHost, conn.RemoteAddr())

	transport := &http3.Transport{
		Dial: func(_ context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}

	return &h3ProxySession{
		conn:      conn,
		udpConn:   udpConn,
		rt:        transport,
		proxyHost: proxyHost,
		token:     token,
		timeout:   timeout,
		tokenMu:   sync.RWMutex{},
		health:    sessionFailureTracker{mu: sync.Mutex{}, openTimeoutTargets: nil, badGatewayTargets: nil},
		closeOnce: sync.Once{},
		closeErr:  nil,
	}, nil
}

//nolint:dupl // mirrored h2 implementation above; the two transports are deliberately parallel
func (s *h3ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	reqBody := newTunnelWriteBuffer(defaultTunnelWriteBufSize)

	resp, cancel, err := roundTripWithOpenTimeout(s.timeout, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+authority, reqBody)
		if err != nil {
			return nil, fmt.Errorf("creating h3 CONNECT request: %w", err)
		}

		req.Host = authority
		req.URL.Host = s.proxyHost
		req.Header.Set("Proxy-Authorization", "Bearer "+s.bearerToken())

		return s.rt.RoundTrip(req)
	})
	if err != nil {
		reqBody.failRead(io.ErrClosedPipe)

		return nil, s.health.observe(authority, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cancel()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, connectErrorBodyLimit))
		_ = resp.Body.Close()

		reqBody.failRead(io.ErrClosedPipe)

		return nil, s.health.observe(authority, &proxyConnectHTTPError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
			body:       strings.TrimSpace(string(body)),
		})
	}

	_ = s.health.observe(authority, nil)

	return &tunnelConn{
		reader:    resp.Body,
		writer:    reqBody,
		reqBody:   reqBody,
		name:      "h3-connect-stream",
		cancel:    cancel,
		closeOnce: sync.Once{},
		readOnce:  sync.Once{},
		writeOnce: sync.Once{},
		closeErr:  nil,
		readErr:   nil,
		writeErr:  nil,
	}, nil
}

func (s *h3ProxySession) UpdateToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return errEmptySessionToken
	}

	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()

	return nil
}

func (s *h3ProxySession) Close() error {
	s.closeOnce.Do(func() {
		if s.rt != nil {
			_ = s.rt.Close()
		}

		if s.conn != nil {
			s.closeErr = s.conn.CloseWithError(0, "")
		}

		if s.udpConn != nil {
			closeErr := s.udpConn.Close()
			if s.closeErr == nil {
				s.closeErr = closeErr
			}
		}
	})

	return s.closeErr
}

func (s *h3ProxySession) bearerToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()

	return s.token
}

// tunnelWriteBuffer is a bounded, concurrency-safe ring buffer used as the
// request body of a CONNECT tunnel. It replaces io.Pipe, whose every write
// blocks until a reader consumes it: here a writer can run ahead of the HTTP
// transport by up to the buffer size, which keeps upload throughput from being
// bounded by a goroutine hand-off per write.
type tunnelWriteBuffer struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	buf      []byte
	n        int
	off      int
	closed   bool
	readErr  error
}

func newTunnelWriteBuffer(size int) *tunnelWriteBuffer {
	if size < 1 {
		size = defaultTunnelWriteBufSize
	}

	buffer := &tunnelWriteBuffer{
		mu:       sync.Mutex{},
		notEmpty: nil,
		notFull:  nil,
		buf:      make([]byte, size),
		n:        0,
		off:      0,
		closed:   false,
		readErr:  nil,
	}
	buffer.notEmpty = sync.NewCond(&buffer.mu)
	buffer.notFull = sync.NewCond(&buffer.mu)

	return buffer
}

// Read drains buffered data, blocking while the buffer is empty and still
// open. A read that reaches the end of the ring returns a short read rather
// than wrapping, which io.Reader permits.
func (b *tunnelWriteBuffer) Read(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.n == 0 && b.readErr == nil && !b.closed {
		b.notEmpty.Wait()
	}

	if b.n == 0 {
		if b.readErr != nil {
			return 0, b.readErr
		}

		return 0, io.EOF
	}

	end := min(b.off+b.n, len(b.buf))

	n := copy(data, b.buf[b.off:end])
	b.off = (b.off + n) % len(b.buf)
	b.n -= n
	b.notFull.Broadcast()

	return n, nil
}

// Write blocks only while the buffer is full, so bursts smaller than the
// buffer complete without waiting for the reader.
func (b *tunnelWriteBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := 0

	for len(data) > 0 {
		for b.n == len(b.buf) && b.readErr == nil && !b.closed {
			b.notFull.Wait()
		}

		if b.readErr != nil {
			return total, b.readErr
		}

		if b.closed {
			return total, io.ErrClosedPipe
		}

		space := len(b.buf) - b.n
		head := (b.off + b.n) % len(b.buf)

		writable := min(space, len(b.buf)-head, len(data))

		copy(b.buf[head:], data[:writable])
		b.n += writable
		data = data[writable:]
		total += writable

		b.notEmpty.Broadcast()
	}

	return total, nil
}

// Close signals end of stream. Buffered data stays readable so a half-closed
// tunnel still flushes what the client already wrote.
func (b *tunnelWriteBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()

	return nil
}

// failRead makes pending and future reads fail with err, unblocking the HTTP/2
// request body writer when the tunnel is torn down.
func (b *tunnelWriteBuffer) failRead(err error) {
	b.mu.Lock()
	if b.readErr == nil {
		b.readErr = err
	}

	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()
	b.mu.Unlock()
}

type tunnelConn struct {
	reader  io.ReadCloser
	writer  *tunnelWriteBuffer
	reqBody *tunnelWriteBuffer
	cancel  context.CancelFunc
	name    tunnelAddr

	closeOnce sync.Once
	readOnce  sync.Once
	writeOnce sync.Once
	closeErr  error
	readErr   error
	writeErr  error
}

func (c *tunnelConn) Read(data []byte) (int, error) {
	readCount, err := c.reader.Read(data)
	if err != nil {
		return readCount, fmt.Errorf("reading tunnel stream: %w", err)
	}

	return readCount, nil
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *tunnelConn) Close() error {
	c.closeOnce.Do(func() {
		writeErr := c.CloseWrite()

		readErr := c.CloseRead()

		if c.reqBody != nil {
			// Unblock the transport if it is still reading the request body,
			// and discard anything the client wrote but never got flushed.
			c.reqBody.failRead(io.ErrClosedPipe)
		}

		if c.cancel != nil {
			c.cancel()
		}

		if writeErr != nil {
			c.closeErr = writeErr
		} else {
			c.closeErr = readErr
		}
	})

	return c.closeErr
}

func (c *tunnelConn) CloseRead() error {
	c.readOnce.Do(func() {
		if c.reader != nil {
			c.readErr = c.reader.Close()
		}
	})

	return c.readErr
}

func (c *tunnelConn) CloseWrite() error {
	c.writeOnce.Do(func() {
		if c.writer != nil {
			c.writeErr = c.writer.Close()
		}
	})

	return c.writeErr
}

func (c *tunnelConn) LocalAddr() net.Addr              { return c.name }
func (c *tunnelConn) RemoteAddr() net.Addr             { return c.name }
func (c *tunnelConn) SetDeadline(time.Time) error      { return errTunnelDeadline }
func (c *tunnelConn) SetReadDeadline(time.Time) error  { return errTunnelDeadline }
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return errTunnelDeadline }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tcp" }
func (a tunnelAddr) String() string  { return string(a) }

type managedSession struct {
	session   proxySession
	rawToken  string
	expiresAt time.Time
	refs      int
	accepting bool
}

type proxyControllerConfig struct {
	Guardian   string
	ProxyURL   *url.URL
	Timeout    time.Duration
	Auth       *runtimeAuth
	Pass       *vpnclient.ProxyPassInfo
	UseH3      bool
	Sessions   int
	StatusFile string
	TokenPool  *sessionTokenPool // optional; enables automatic token rotation on quota exhaustion
}

type proxyController struct {
	guardian string
	proxyURL *url.URL
	timeout  time.Duration

	sessionFactory func(token string) (proxySession, error)
	refreshSession func() error
	tokenPool      *sessionTokenPool

	renewMu    sync.Mutex
	mu         sync.Mutex
	auth       *runtimeAuth
	current    *managedSession
	statusFile string
	closed     bool
	done       chan struct{}

	closeOnce sync.Once
	closeErr  error
}

type proxyRuntimeStatus struct {
	UpdatedAt          string `json:"updated_at"`
	PID                int    `json:"pid"`
	ProxyPassExpiresAt string `json:"proxy_pass_expires_at"`
	SecondsUntilExpiry int64  `json:"seconds_until_expiry"`
	Accepting          bool   `json:"accepting"`
	Reason             string `json:"reason"`
}

func newProxyController(cfg proxyControllerConfig) (*proxyController, error) {
	var baseFactory func(token string) (proxySession, error)
	if cfg.UseH3 {
		baseFactory = func(token string) (proxySession, error) {
			return newH3ProxySession(cfg.ProxyURL, token, cfg.Timeout)
		}
	} else {
		baseFactory = func(token string) (proxySession, error) {
			return newH2ProxySession(cfg.ProxyURL, token, cfg.Timeout)
		}
	}

	sessions := cfg.Sessions
	if sessions < 1 {
		sessions = defaultUpstreamConnections
	}

	factory := func(token string) (proxySession, error) {
		if sessions == 1 {
			return baseFactory(token)
		}

		var tokenMu sync.RWMutex

		createToken := token

		return newProxySessionPool(sessions, func() (proxySession, error) {
			tokenMu.RLock()

			currentToken := createToken

			tokenMu.RUnlock()

			return baseFactory(currentToken)
		}, func(newToken string) {
			tokenMu.Lock()
			createToken = newToken
			tokenMu.Unlock()
		})
	}

	session, err := factory(cfg.Pass.RawToken)
	if err != nil {
		return nil, err
	}

	controller := &proxyController{
		guardian:       cfg.Guardian,
		proxyURL:       cfg.ProxyURL,
		timeout:        cfg.Timeout,
		sessionFactory: factory,
		refreshSession: nil,
		tokenPool:      cfg.TokenPool,
		renewMu:        sync.Mutex{},
		mu:             sync.Mutex{},
		auth:           cfg.Auth,
		statusFile:     cfg.StatusFile,
		closed:         false,
		done:           make(chan struct{}),
		closeOnce:      sync.Once{},
		closeErr:       nil,
		current: &managedSession{
			session:   session,
			rawToken:  cfg.Pass.RawToken,
			expiresAt: cfg.Pass.ExpiresAt(),
			refs:      0,
			accepting: true,
		},
	}
	controller.writeStatus("startup")

	return controller, nil
}

func (c *proxyController) OpenTunnel(authority string) (net.Conn, error) {
	return c.openTunnel(authority, "")
}

func (c *proxyController) OpenTunnelForClient(authority, clientKey string) (net.Conn, error) {
	return c.openTunnel(authority, clientKey)
}

func (c *proxyController) Close() error {
	c.closeOnce.Do(func() {
		if c.done != nil {
			close(c.done)
		}

		c.mu.Lock()
		defer c.mu.Unlock()

		c.closed = true
		if c.current != nil {
			c.current.accepting = false
			if c.current.session != nil {
				c.closeErr = c.current.session.Close()
				c.current.session = nil
			}
		}
	})
	c.writeStatus("closed")

	return c.closeErr
}

func (c *proxyController) openTunnel(authority, clientKey string) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt <= maxOpenTunnelRebuildRetries; attempt++ {
		var failedSession *managedSession

		managedSess, release, err := c.acquireSession()

		switch {
		case err != nil:
			if c.isClosed() {
				return nil, err
			}

			if !errors.Is(err, errNoUsableProxySession) || lastErr == nil {
				lastErr = err
			}
		case !isSessionAlive(managedSess.session):
			// The keepalive already saw this session die; rebuild it instead of
			// spending a request to rediscover that.
			lastErr = errProxySessionUnhealthy
			failedSession = managedSess
			c.markSessionUnusable(managedSess)
			release()
		default:
			var conn net.Conn
			if affinitySession, ok := managedSess.session.(clientAffinityTunnelOpener); ok {
				conn, err = affinitySession.OpenTunnelForClient(authority, clientKey)
			} else {
				conn, err = managedSess.session.OpenTunnel(authority)
			}

			if err == nil {
				return &managedTunnelConn{
					Conn:    conn,
					release: release,
					once:    sync.Once{},
				}, nil
			}

			if !shouldRebuildProxySession(err) {
				release()

				return nil, fmt.Errorf("opening upstream tunnel: %w", err)
			}

			lastErr = err
			failedSession = managedSess
			c.markSessionUnusable(managedSess)
			release()
		}

		if attempt == maxOpenTunnelRebuildRetries {
			break
		}

		logWarnf("upstream tunnel open failed; rebuilding "+
			"proxy session attempt=%d max=%d err=%s", attempt+1, maxOpenTunnelRebuildRetries, logErr(lastErr))

		err = c.rebuildSession(failedSession)
		if err != nil {
			lastErr = fmt.Errorf("rebuilding upstream proxy session: %w", err)
		}
	}

	return nil, lastErr
}

func (c *proxyController) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closed
}

func (c *proxyController) acquireSession() (*managedSession, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, nil, errNoUsableProxySession
	}

	if c.current == nil || !c.current.accepting {
		return nil, nil, errNoUsableProxySession
	}

	if time.Now().After(c.current.expiresAt) {
		c.current.accepting = false
		c.maybeCloseLocked(c.current)

		return nil, nil, errNoUsableProxySession
	}

	managedSess := c.current
	managedSess.refs++

	return managedSess, func() { c.releaseSession(managedSess) }, nil
}

func (c *proxyController) releaseSession(managedSess *managedSession) {
	c.mu.Lock()
	defer c.mu.Unlock()

	managedSess.refs--
	c.maybeCloseLocked(managedSess)
}

func (c *proxyController) markSessionUnusable(managedSess *managedSession) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if managedSess == nil || c.current != managedSess {
		return
	}

	managedSess.accepting = false
	c.maybeCloseLocked(managedSess)
}

func (c *proxyController) maybeCloseLocked(managedSess *managedSession) {
	if managedSess == nil || managedSess.accepting || managedSess.refs > 0 || managedSess.session == nil {
		return
	}

	_ = managedSess.session.Close()
	managedSess.session = nil
}

func (c *proxyController) swapSession(newSession proxySession, rawToken string, expiresAt time.Time) bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()

		_ = newSession.Close()

		return false
	}

	old := c.current

	c.current = &managedSession{
		session:   newSession,
		rawToken:  rawToken,
		expiresAt: expiresAt,
		refs:      0,
		accepting: true,
	}

	if old != nil {
		old.accepting = false
		c.maybeCloseLocked(old)
	}
	c.mu.Unlock()
	c.writeStatus("session_swapped")

	return true
}

func (c *proxyController) disableExpiredSession(now time.Time) {
	c.mu.Lock()
	changed := false

	if c.current != nil && c.current.accepting && !now.Before(c.current.expiresAt) {
		c.current.accepting = false
		c.maybeCloseLocked(c.current)

		changed = true
	}
	c.mu.Unlock()

	if changed {
		c.writeStatus("expired")
	}
}

func (c *proxyController) currentExpiry() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.current == nil {
		return time.Time{}
	}

	return c.current.expiresAt
}

func (c *proxyController) currentStatus(reason string) proxyRuntimeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	status := proxyRuntimeStatus{
		UpdatedAt:          time.Now().Format(time.RFC3339),
		PID:                os.Getpid(),
		ProxyPassExpiresAt: "",
		SecondsUntilExpiry: 0,
		Accepting:          false,
		Reason:             reason,
	}
	if c.current != nil {
		status.ProxyPassExpiresAt = c.current.expiresAt.Format(time.RFC3339)
		status.SecondsUntilExpiry = int64(time.Until(c.current.expiresAt).Round(time.Second) / time.Second)
		status.Accepting = c.current.accepting
	}

	return status
}

func (c *proxyController) writeStatus(reason string) {
	if c.statusFile == "" {
		return
	}

	status := c.currentStatus(reason)

	err := c.writeStatusFile(status)
	if err != nil {
		logWarnf("writing status file failed path=%s err=%s", c.statusFile, logErr(err))
	}
}

func (c *proxyController) writeStatusFile(status proxyRuntimeStatus) error {
	if c.statusFile == "" {
		return nil
	}

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling runtime status: %w", err)
	}

	data = append(data, '\n')

	dir := filepath.Dir(c.statusFile)

	// G301: the status directory stays world-readable for unprivileged supervisor tooling.
	err = os.MkdirAll(dir, statusDirMode)
	if err != nil {
		return fmt.Errorf("creating status directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(c.statusFile)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating status temp file: %w", err)
	}

	tmpName := tmp.Name()

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return fmt.Errorf("writing status temp file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		_ = os.Remove(tmpName)

		return fmt.Errorf("closing status temp file: %w", err)
	}

	err = os.Rename(tmpName, c.statusFile)
	if err != nil {
		removeErr := os.Remove(c.statusFile)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			_ = os.Remove(tmpName)

			return fmt.Errorf("replacing status file: %w", err)
		}

		retryErr := os.Rename(tmpName, c.statusFile)
		if retryErr != nil {
			_ = os.Remove(tmpName)

			return fmt.Errorf("replacing status file after retry: %w", retryErr)
		}
	}

	return nil
}

func (c *proxyController) hasUsableSessionOtherThan(failedSession *managedSession, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.current == nil || !c.current.accepting {
		return false
	}

	if failedSession != nil && c.current == failedSession {
		return false
	}

	return now.Before(c.current.expiresAt)
}

func (c *proxyController) runRenewalLoop() {
	for {
		if c.isClosed() {
			return
		}

		expiry := c.currentExpiry()
		sleep := c.nextRenewalDelay()
		logInfof("proxy pass renewal scheduled next_expiry=%s delay=%s", expiry.Format(time.RFC3339), sleep)

		if !c.sleepOrDone(sleep) {
			return
		}

		logInfof("proxy pass renewal starting")

		timedOut, err := c.renewWithTimeout(proxyPassRenewTimeout)
		if timedOut {
			logErrorf("proxy pass renewal timed out after %s; exiting for supervisor restart", proxyPassRenewTimeout)
			os.Exit(1)
		} else if err != nil {
			now := time.Now()

			logWarnf("proxy pass renewal failed: %s", logErr(err))
			c.disableExpiredSession(now)
			logDebugf("proxy pass renewal retry scheduled delay=%s", proxyPassRetryDelay)

			if !c.sleepOrDone(proxyPassRetryDelay) {
				return
			}

			continue
		}
	}
}

func (c *proxyController) renewWithTimeout(timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		err := c.renew()

		return false, err
	}

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- c.renew()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-resultCh:
		return false, err
	case <-timer.C:
		return true, nil
	case <-c.done:
		return false, nil
	}
}

func (c *proxyController) sleepOrDone(delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-c.done:
			return false
		default:
			return true
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-c.done:
		return false
	}
}

func (c *proxyController) nextRenewalDelay() time.Duration {
	expiry := c.currentExpiry()
	if expiry.IsZero() {
		return proxyPassRetryDelay
	}

	renewAt := expiry.Add(-proxyPassRenewLead)

	delay := time.Until(renewAt)
	if delay < 0 {
		return 0
	}

	return delay
}

func (c *proxyController) renew() error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	return c.renewLocked()
}

func (c *proxyController) rebuildSession(failedSession *managedSession) error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	if c.hasUsableSessionOtherThan(failedSession, time.Now()) {
		logDebugf("skipping proxy session rebuild: another usable session is already active")

		return nil
	}

	if c.refreshSession != nil {
		return c.refreshSession()
	}

	return c.renewLocked()
}

func (c *proxyController) renewLocked() error {
	pass, err := c.acquireUsablePass()
	if err != nil {
		return err
	}

	return c.adoptPass(pass)
}

// acquireUsablePass returns a proxy pass whose monthly quota is not yet
// exhausted. A Guardian token rejection is recovered from by refreshing the
// OAuth token and activating the account; when the current account's quota
// runs out (HTTP 429 or zero remaining) and a session token pool is
// configured, it activates the next token from the pool.
//
//nolint:gocognit,cyclop // token rotation state machine: each branch is a distinct recovery path
func (c *proxyController) acquireUsablePass() (*vpnclient.ProxyPassInfo, error) {
	auth, err := c.ensureOAuthToken()
	if err != nil {
		return nil, err
	}

	for {
		// Each fetch attempt gets its own deadline so token rotation
		// retries are not starved by earlier slow attempts.
		pass, fetchErr := fetchProxyPassCtx(c.guardian, auth.Token.AccessToken)
		if fetchErr == nil && !isQuotaExhausted(pass) {
			return pass, nil
		}

		if fetchErr != nil &&
			!errors.Is(fetchErr, vpnclient.ErrQuotaExceeded) &&
			!errors.Is(fetchErr, vpnclient.ErrTokenInvalid) {
			return nil, fetchErr
		}

		if errors.Is(fetchErr, vpnclient.ErrTokenInvalid) {
			logInfof("OAuth access was rejected by Guardian during renewal; refreshing token")

			refreshed, refreshErr := refreshRuntimeAuth(auth)
			if refreshErr == nil {
				auth = refreshed

				c.mu.Lock()
				c.auth = refreshed
				c.mu.Unlock()

				pass, fetchErr = fetchProxyPassCtx(c.guardian, auth.Token.AccessToken)
				if fetchErr == nil && !isQuotaExhausted(pass) {
					return pass, nil
				}
			}

			if errors.Is(fetchErr, vpnclient.ErrTokenInvalid) {
				logInfof("Guardian account requires activation during proxy pass renewal; activating")

				ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
				_, activateErr := vpnclient.ActivateGuardian(ctx, c.guardian, auth.Token.AccessToken)

				cancel()

				if activateErr != nil {
					return nil, fmt.Errorf("activating Guardian account during renewal: %w", activateErr)
				}

				logInfof("Guardian account activated during proxy pass renewal")

				pass, fetchErr = fetchProxyPassCtx(c.guardian, auth.Token.AccessToken)
				if fetchErr == nil && !isQuotaExhausted(pass) {
					return pass, nil
				}
			}
		}

		// Token unusable on this account (quota exhausted or rejected).
		if c.tokenPool == nil {
			if fetchErr != nil {
				return nil, fetchErr
			}

			return pass, nil
		}

		if errors.Is(fetchErr, vpnclient.ErrTokenInvalid) {
			logWarnf("session token rejected by Guardian; switching to the next token")
		} else {
			logWarnf("session token quota exhausted; switching to the next token")
		}

		auth, err = c.nextTokenAuth()
		if err != nil {
			return nil, err
		}
	}
}

// nextTokenAuth activates the next session token from the pool and makes it
// the controller's current auth.
func (c *proxyController) nextTokenAuth() (*runtimeAuth, error) {
	auth, err := activateNextPoolToken(c.tokenPool)
	if err != nil {
		return nil, fmt.Errorf("activating next session token: %w", err)
	}

	err = vpnclient.SaveTokens(auth.Token)
	if err != nil {
		logWarnf("saving tokens failed: %v", err)
	}

	c.mu.Lock()
	c.auth = auth
	c.mu.Unlock()

	return auth, nil
}

// adoptPass applies pass to the current session: when the session supports
// in-place token updates the session is retained, otherwise a fresh session
// pool is built and swapped in while active tunnels drain gracefully.
func (c *proxyController) adoptPass(pass *vpnclient.ProxyPassInfo) error {
	logProxyPassTimeCorrection(pass)

	err := c.updateCurrentSessionToken(pass.RawToken, pass.ExpiresAt())
	if err != nil {
		logDebugf("existing upstream session cannot accept renewed proxy pass; rebuilding err=%s", logErr(err))
	} else {
		c.writeStatus("token_updated")
		logInfof("proxy pass renewed successfully next_expiry=%s session=retained", pass.ExpiresAt().Format(time.RFC3339))

		return nil
	}

	session, err := c.sessionFactory(pass.RawToken)
	if err != nil {
		return fmt.Errorf("building replacement upstream session: %w", err)
	}

	if !c.swapSession(session, pass.RawToken, pass.ExpiresAt()) {
		return errNoUsableProxySession
	}

	logInfof("proxy pass renewed successfully next_expiry=%s", pass.ExpiresAt().Format(time.RFC3339))

	return nil
}

// runQuotaMonitorLoop periodically checks the remaining monthly quota and
// rotates to the next session token once it is exhausted, without waiting
// for the proxy pass itself to expire.
func (c *proxyController) runQuotaMonitorLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.checkQuota()
		}
	}
}

func (c *proxyController) checkQuota() {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()

	pass, err := c.acquireUsablePass()
	if err != nil {
		logWarnf("quota check failed: %s", logErr(err))

		return
	}

	c.mu.Lock()
	unchanged := c.current != nil && c.current.rawToken == pass.RawToken
	c.mu.Unlock()

	if unchanged {
		return
	}

	err = c.adoptPass(pass)
	if err != nil {
		logWarnf("quota check: could not rebuild proxy sessions: %s", logErr(err))

		return
	}

	logInfof("proxy sessions refreshed after token rotation")
}

func (c *proxyController) updateCurrentSessionToken(token string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.current == nil || !c.current.accepting || !time.Now().Before(c.current.expiresAt) {
		return errNoUsableProxySession
	}

	updater, ok := c.current.session.(proxySessionTokenUpdater)
	if !ok {
		return errSessionTokenUpdateUnsupported
	}

	err := updater.UpdateToken(token)
	if err != nil {
		return fmt.Errorf("updating current session token: %w", err)
	}

	c.current.rawToken = token
	c.current.expiresAt = expiresAt

	return nil
}

func (c *proxyController) ensureOAuthToken() (*runtimeAuth, error) {
	c.mu.Lock()
	auth := c.auth
	c.mu.Unlock()

	now := time.Now()
	if auth != nil && auth.accessTokenValid(now) {
		return auth, nil
	}

	if auth == nil || auth.Token == nil || auth.Token.RefreshToken == "" {
		return nil, errNoRefreshTokenForRenewal
	}

	logInfof("refreshing OAuth token")

	refreshed, err := refreshRuntimeAuth(auth)
	if err != nil {
		return nil, fmt.Errorf("refreshing OAuth token for renewal: %w", err)
	}

	c.mu.Lock()
	c.auth = refreshed
	c.mu.Unlock()
	logInfof("OAuth token refreshed")

	return refreshed, nil
}

type managedTunnelConn struct {
	net.Conn

	release func()
	once    sync.Once
}

func (c *managedTunnelConn) Close() error {
	var err error

	c.once.Do(func() {
		closeErr := c.Conn.Close()
		if closeErr != nil {
			err = fmt.Errorf("closing managed tunnel connection: %w", closeErr)
		}

		if c.release != nil {
			c.release()
		}
	})

	return err
}

func (c *managedTunnelConn) CloseRead() error {
	if closeReader, ok := c.Conn.(interface{ CloseRead() error }); ok {
		err := closeReader.CloseRead()
		if err != nil {
			return fmt.Errorf("half-closing managed tunnel read side: %w", err)
		}
	}

	return nil
}

func (c *managedTunnelConn) CloseWrite() error {
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		err := closeWriter.CloseWrite()
		if err != nil {
			return fmt.Errorf("half-closing managed tunnel write side: %w", err)
		}
	}

	return nil
}
