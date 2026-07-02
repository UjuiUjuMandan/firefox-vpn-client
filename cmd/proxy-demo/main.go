package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	vpnclient "firefox-vpn-client"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
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
	proxyPassRenewLead          = 2 * time.Minute
	proxyPassRetryDelay         = 30 * time.Second
	oauthRefreshLead            = 2 * time.Minute
	maxOpenTunnelRebuildRetries = 3
	defaultHandshakeTimeout     = 10 * time.Second
	defaultMaxConnections       = 256
)

var (
	errProxyHTTP2Unavailable = errors.New("proxy did not negotiate HTTP/2")
	errProxyHTTP3Unavailable = errors.New("proxy did not negotiate HTTP/3")
	errNoUsableProxySession  = errors.New("no usable upstream proxy session")
	errTunnelDeadline        = errors.New("deadlines are not supported for HTTP CONNECT tunnel streams")
	verboseLogs              bool
	logMu                    sync.Mutex
)

func logEvent(level, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(os.Stderr, "%s %-5s %s\n", time.Now().Format(time.RFC3339), level, message)
}

func logDebug(format string, args ...any) {
	if !verboseLogs {
		return
	}
	logEvent("DEBUG", format, args...)
}

func logInfo(format string, args ...any) {
	logEvent("INFO", format, args...)
}

func logWarn(format string, args ...any) {
	logEvent("WARN", format, args...)
}

func logError(format string, args ...any) {
	logEvent("ERROR", format, args...)
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

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "Usage of proxy-demo:")
		fmt.Fprintln(out, "  proxy-demo [-proxy https://HOST:PORT] [-listen 127.0.0.1:1080] [-h3] [-print-info]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "This program logs in to Firefox Accounts, fetches a VPN proxy pass, and")
		fmt.Fprintln(out, "exposes a local SOCKS5 CONNECT proxy over a single upstream HTTP/2 or HTTP/3 connection.")
		fmt.Fprintln(out)
		flag.PrintDefaults()
	}

	guardianFlag := flag.String("guardian", vpnclient.GuardianEndpointDefault, "Guardian API endpoint")
	listenFlag := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	loginFlag := flag.Bool("login", false, "Force fresh login (ignore saved refresh token)")
	sessionTokenFlag := flag.String("session-token", "", "Use existing session token directly")
	printInfoFlag := flag.Bool("print-info", false, "Print user info, quota info, and server list, then exit")
	proxyFlag := flag.String("proxy", "", "Upstream proxy URL or host:port; random CONNECT server if omitted")
	timeoutFlag := flag.Duration("timeout", 20*time.Second, "Upstream dial and handshake timeout")
	handshakeTimeoutFlag := flag.Duration("handshake-timeout", defaultHandshakeTimeout, "Maximum time allowed for a client SOCKS5 handshake; 0 disables the limit")
	maxConnsFlag := flag.Int("max-conns", defaultMaxConnections, "Maximum concurrent client connections; 0 disables the limit")
	useH3Flag := flag.Bool("h3", false, "Use HTTP/3 (QUIC/UDP) instead of HTTP/2 (TCP) for the upstream connection")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose per-connection logs, including CONNECT target hosts")
	flag.Parse()
	verboseLogs = *verboseFlag

	runtimeAuth, tokenSource, countries := prepareDemoInputs(
		*loginFlag,
		strings.TrimSpace(*sessionTokenFlag),
		true,
	)

	selectedProxy, err := resolveProxy(strings.TrimSpace(*proxyFlag), countries)
	if err != nil {
		logError("selecting proxy failed: %v", err)
		os.Exit(1)
	}

	proxyURL, err := normalizeProxyURL(selectedProxy.Addr)
	if err != nil {
		logError("invalid proxy %q: %v", selectedProxy.Addr, err)
		os.Exit(1)
	}

	pass, err := vpnclient.FetchProxyPass(*guardianFlag, runtimeAuth.Token.AccessToken)
	if err != nil {
		var guardianErr *vpnclient.GuardianHTTPError
		if errors.As(err, &guardianErr) && guardianErr.StatusCode == http.StatusForbidden {
			logInfo("Guardian account is not activated for Firefox VPN proxy access; activating")
			if _, activateErr := vpnclient.ActivateGuardian(*guardianFlag, runtimeAuth.Token.AccessToken); activateErr != nil {
				logError("activating Guardian account failed: %v", activateErr)
				os.Exit(1)
			}
			logInfo("Guardian account activated")
			pass, err = vpnclient.FetchProxyPass(*guardianFlag, runtimeAuth.Token.AccessToken)
		}
		if err != nil {
			logError("fetching proxy pass failed: %v", err)
			os.Exit(1)
		}
	}
	if *printInfoFlag {
		printRuntimeInfo(*guardianFlag, runtimeAuth.Token.AccessToken, pass, countries)
		return
	}
	sessionStart := time.Now()
	controller, err := newProxyController(proxyControllerConfig{
		Guardian: *guardianFlag,
		ProxyURL: proxyURL,
		Timeout:  *timeoutFlag,
		Auth:     runtimeAuth,
		Pass:     pass,
		UseH3:    *useH3Flag,
	})
	if err != nil {
		switch {
		case errors.Is(err, errProxyHTTP2Unavailable):
			logError("upstream proxy does not support HTTP/2; refusing to start because this server must use a single upstream TCP connection")
		case errors.Is(err, errProxyHTTP3Unavailable):
			logError("upstream proxy did not negotiate HTTP/3 (h3 ALPN); the server may not support QUIC")
		default:
			logError("establishing upstream proxy session failed: %v", err)
		}
		os.Exit(1)
	}
	localToExitLatency := time.Since(sessionStart).Round(time.Millisecond)
	defer controller.Close()
	go controller.runRenewalLoop()

	ln, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		logError("listening on %s failed: %v", *listenFlag, err)
		os.Exit(1)
	}
	defer ln.Close()

	logInfo("SOCKS5 proxy started listen=%s upstream=%s auth_source=%q proxy_pass_exp=%s max_conns=%d handshake_timeout=%s connect_timeout=%s verbose=%v",
		ln.Addr().String(),
		selectedProxy.Addr,
		tokenSource,
		pass.ExpiresAt().Format(time.RFC3339),
		*maxConnsFlag,
		handshakeTimeoutFlag.String(),
		timeoutFlag.String(),
		verboseLogs,
	)
	if *useH3Flag {
		logInfo("transport=http3 mode=single-upstream-connection renewal=background")
	} else {
		logInfo("transport=http2 mode=single-upstream-connection renewal=background")
	}
	logInfo("exit selected country=%q country_code=%s city=%q city_code=%s proxy=%s local_to_exit_latency=%s",
		selectedProxy.CountryNameOrUnknown(),
		selectedProxy.CountryCodeOrUnknown(),
		selectedProxy.CityNameOrUnknown(),
		selectedProxy.CityCodeOrUnknown(),
		selectedProxy.Addr,
		localToExitLatency,
	)

	server := newSocksServer(controller, *handshakeTimeoutFlag, *maxConnsFlag)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logWarn("accept failed: %v", err)
			continue
		}
		go server.handleConn(conn)
	}
}

func prepareDemoInputs(forceLogin bool, sessionToken string, needServerList bool) (*runtimeAuth, string, []vpnclient.Country) {

	var token *vpnclient.TokenResponse
	var tokenSource string

	if sessionToken != "" {
		fmt.Print("Using provided session token... ")
		var err error
		token, err = vpnclient.FxaOAuthToken(sessionToken)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		tokenSource = "session-token flag"
	} else {
		token, tokenSource = obtainOAuthToken(forceLogin)
	}

	if err := vpnclient.SaveTokens(token); err != nil {
		logWarn("saving tokens failed: %v", err)
	}

	var countries []vpnclient.Country
	var err error
	if needServerList {
		countries, err = vpnclient.FetchServerList()
		if err != nil {
			logWarn("fetching server list failed: %v", err)
		}
	}

	return &runtimeAuth{
		Token:      token,
		ObtainedAt: time.Now(),
	}, tokenSource, countries
}

func printRuntimeInfo(guardian, accessToken string, pass *vpnclient.ProxyPassInfo, countries []vpnclient.Country) {
	fmt.Println("=== User Info ===")
	ent, err := vpnclient.FetchUserInfo(guardian, accessToken)
	if err != nil {
		fmt.Printf("Warning: could not fetch user info: %v\n", err)
	} else {
		fmt.Printf("Subscribed:    %v\n", ent.Subscribed)
		fmt.Printf("UID:           %d\n", ent.UID)
		fmt.Printf("Max Bytes:     %s\n", ent.MaxBytes)
	}

	fmt.Println()
	fmt.Println("=== Proxy Pass ===")
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

	fmt.Println()
	fmt.Println("=== Server List ===")
	if len(countries) == 0 {
		fmt.Println("No servers found in Remote Settings.")
		return
	}
	vpnclient.PrintServerList(countries)
}

func obtainOAuthToken(forceLogin bool) (*vpnclient.TokenResponse, string) {
	if !forceLogin {
		saved, err := vpnclient.LoadTokens()
		if err == nil && saved.RefreshToken != "" {
			fmt.Print("Refreshing token... ")
			token, err := vpnclient.FxaRefreshToken(saved.RefreshToken)
			if err != nil {
				fmt.Printf("failed: %v\n", err)
				logWarn("saved tokens were preserved; retry by restarting the program, or use -login to force a fresh login")
				os.Exit(1)
			}
			fmt.Println("OK")
			return token, "refresh token"
		}
	}

	email, password := promptCredentials()

	fmt.Print("Logging in... ")
	loginResp, err := vpnclient.FxaLogin(email, password)
	if err != nil {
		fmt.Printf("failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Print("Getting OAuth token... ")
	token, err := vpnclient.FxaOAuthToken(loginResp.SessionToken)
	if err != nil {
		fmt.Printf("failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	return token, "fresh login"
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
		logError("reading password failed: %v", err)
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

func (p proxyCandidate) CountryNameOrUnknown() string {
	if p.CountryName == "" {
		return "unknown"
	}
	return p.CountryName
}

func (p proxyCandidate) CountryCodeOrUnknown() string {
	if p.CountryCode == "" {
		return "unknown"
	}
	return p.CountryCode
}

func (p proxyCandidate) CityNameOrUnknown() string {
	if p.CityName == "" {
		return "unknown"
	}
	return p.CityName
}

func (p proxyCandidate) CityCodeOrUnknown() string {
	if p.CityCode == "" {
		return "unknown"
	}
	return p.CityCode
}

func resolveProxy(proxyFlag string, countries []vpnclient.Country) (proxyCandidate, error) {
	if proxyFlag != "" {
		if matched, ok := findProxyCandidate(proxyFlag, countries); ok {
			matched.Addr = proxyFlag
			return matched, nil
		}
		return proxyCandidate{Addr: proxyFlag}, nil
	}

	proxies := connectProxyCandidates(countries)
	if len(proxies) == 0 {
		return proxyCandidate{}, fmt.Errorf("no CONNECT proxies available from server list; pass -proxy explicitly")
	}
	return proxies[rand.IntN(len(proxies))], nil
}

func findProxyCandidate(proxyFlag string, countries []vpnclient.Country) (proxyCandidate, bool) {
	target, err := canonicalProxyAddr(proxyFlag)
	if err != nil {
		return proxyCandidate{}, false
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
	return proxyCandidate{}, false
}

func canonicalProxyAddr(raw string) (string, error) {
	proxyURL, err := normalizeProxyURL(raw)
	if err != nil {
		return "", err
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
		return nil, fmt.Errorf("empty proxy value")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("missing proxy host")
	}
	return parsed, nil
}

type tunnelOpener interface {
	OpenTunnel(authority string) (net.Conn, error)
}

type proxySession interface {
	tunnelOpener
	Close() error
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
	connSlots        chan struct{}
}

func newSocksServer(upstream tunnelOpener, handshakeTimeout time.Duration, maxConns int) *socksServer {
	var slots chan struct{}
	if maxConns > 0 {
		slots = make(chan struct{}, maxConns)
	}
	return &socksServer{
		upstream:         upstream,
		handshakeTimeout: handshakeTimeout,
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
		logWarn("client rejected: connection limit reached client=%s", clientAddr)
		_ = conn.Close()
		return
	}
	defer s.releaseConnSlot()
	defer conn.Close()
	logDebug("client connected client=%s", clientAddr)

	if s.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	}
	target, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		logDebug("SOCKS5 handshake failed client=%s reply=%d err=%v", clientAddr, replyCode, err)
		if replyCode != 0 {
			if writeErr := writeSOCKSReply(conn, replyCode, nil); writeErr != nil {
				logDebug("SOCKS5 handshake failure reply failed client=%s reply=%d err=%v", clientAddr, replyCode, writeErr)
			}
		}
		return
	}
	if s.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
	logDebug("SOCKS5 CONNECT requested client=%s target=%s", clientAddr, logTarget(target))

	upstreamConn, err := s.upstream.OpenTunnel(target)
	if err != nil {
		reply := mapUpstreamError(err)
		logWarn("upstream tunnel open failed client=%s target=%s reply=%d err=%s", clientAddr, logTarget(target), reply, logErr(err))
		if writeErr := writeSOCKSReply(conn, reply, nil); writeErr != nil {
			logDebug("SOCKS5 upstream failure reply failed client=%s target=%s reply=%d err=%v", clientAddr, logTarget(target), reply, writeErr)
		}
		return
	}
	defer upstreamConn.Close()

	if err := writeSOCKSReply(conn, socksReplySuccess, conn.LocalAddr()); err != nil {
		logDebug("SOCKS5 success reply failed client=%s target=%s err=%v", clientAddr, logTarget(target), err)
		return
	}

	logDebug("upstream tunnel open succeeded client=%s target=%s", clientAddr, logTarget(target))
	proxyBidirectional(conn, upstreamConn)
	logDebug("client disconnected client=%s target=%s duration=%s", clientAddr, logTarget(target), time.Since(start).Round(time.Millisecond))
}

func handshakeSOCKS5(conn net.Conn) (string, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("unexpected SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
	}

	method := byte(socksAuthNoAccept)
	for _, candidate := range methods {
		if candidate == socksAuthNoAuth {
			method = socksAuthNoAuth
			break
		}
	}
	if _, err := conn.Write([]byte{socksVersion5, method}); err != nil {
		return "", 0, err
	}
	if method == socksAuthNoAccept {
		return "", 0, fmt.Errorf("no supported SOCKS auth methods")
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return "", 0, err
	}
	if reqHeader[0] != socksVersion5 {
		return "", socksReplyFailure, fmt.Errorf("unexpected request version %d", reqHeader[0])
	}
	if reqHeader[1] != socksCmdConnect {
		return "", socksReplyCmdUnsup, fmt.Errorf("unsupported SOCKS command %d", reqHeader[1])
	}

	host, err := readSOCKSAddr(conn, reqHeader[3])
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			return "", socksReplyAtypUnsup, err
		}
		return "", socksReplyFailure, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", socksReplyFailure, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), socksReplySuccess, nil
}

var errUnsupportedAddrType = errors.New("unsupported SOCKS address type")

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypDomain:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", errUnsupportedAddrType
	}
}

func writeSOCKSReply(w io.Writer, rep byte, addr net.Addr) error {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			host = tcpAddr.IP.String()
			port = tcpAddr.Port
		}
	}

	ip := net.ParseIP(host)
	atyp := byte(socksAtypIPv4)
	addrBytes := []byte{0, 0, 0, 0}
	if ip != nil && ip.To4() != nil {
		addrBytes = ip.To4()
	} else if ip != nil && ip.To16() != nil {
		atyp = socksAtypIPv6
		addrBytes = ip.To16()
	}

	reply := make([]byte, 0, 6+len(addrBytes))
	reply = append(reply, socksVersion5, rep, 0x00, atyp)
	reply = append(reply, addrBytes...)
	reply = append(reply, byte(port>>8), byte(port))
	_, err := w.Write(reply)
	return err
}

func mapUpstreamError(err error) byte {
	if errors.Is(err, errNoUsableProxySession) {
		return socksReplyHostUnrch
	}
	if errors.Is(err, errUnsupportedAddrType) {
		return socksReplyAtypUnsup
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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
		return fmt.Sprintf("proxy CONNECT failed: %s", e.status)
	}
	return fmt.Sprintf("proxy CONNECT failed: %s: %s", e.status, e.body)
}

func shouldRebuildProxySession(err error) bool {
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
	if errors.As(err, &timeoutErr) {
		return false
	}
	return true
}

type roundTripResult struct {
	resp *http.Response
	err  error
}

func roundTripWithOpenTimeout(timeout time.Duration, do func(context.Context) (*http.Response, error)) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout <= 0 {
		resp, err := do(ctx)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		return resp, cancel, nil
	}

	resultCh := make(chan roundTripResult, 1)
	go func() {
		resp, err := do(ctx)
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
			result := <-resultCh
			if result.resp != nil && result.resp.Body != nil {
				_ = result.resp.Body.Close()
			}
		}()
		return nil, nil, &tunnelOpenTimeoutError{timeout: timeout}
	}
}

func proxyBidirectional(clientConn, upstreamConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientConn)
		if closeWriter, ok := upstreamConn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		if closeWriter, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()

	wg.Wait()
}

type h2ProxySession struct {
	raw       *tls.Conn
	cc        *http2.ClientConn
	proxyHost string
	token     string
	timeout   time.Duration
}

func newH2ProxySession(proxyURL *url.URL, token string, timeout time.Duration) (*h2ProxySession, error) {
	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyHost = proxyURL.Hostname() + ":443"
	}

	dialer := &net.Dialer{Timeout: timeout}
	proxyTLS, err := tls.DialWithDialer(dialer, "tcp", proxyHost, &tls.Config{
		ServerName: proxyURL.Hostname(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err != nil {
		return nil, err
	}

	if proxyTLS.ConnectionState().NegotiatedProtocol != "h2" {
		_ = proxyTLS.Close()
		return nil, errProxyHTTP2Unavailable
	}

	cc, err := new(http2.Transport).NewClientConn(proxyTLS)
	if err != nil {
		_ = proxyTLS.Close()
		return nil, err
	}
	logInfo("upstream HTTP/2 session established proxy=%s", proxyHost)

	return &h2ProxySession{
		raw:       proxyTLS,
		cc:        cc,
		proxyHost: proxyHost,
		token:     token,
		timeout:   timeout,
	}, nil
}

func (s *h2ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	pr, pw := io.Pipe()
	resp, cancel, err := roundTripWithOpenTimeout(s.timeout, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+authority, pr)
		if err != nil {
			return nil, err
		}
		req.Host = authority
		req.URL.Host = s.proxyHost
		req.Header.Set("Proxy-Authorization", "Bearer "+s.token)
		return s.cc.RoundTrip(req)
	})
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, &proxyConnectHTTPError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
			body:       strings.TrimSpace(string(body)),
		}
	}

	return &tunnelConn{
		reader:  resp.Body,
		writer:  pw,
		reqBody: pr,
		name:    "h2-connect-stream",
		cancel:  cancel,
	}, nil
}

func (s *h2ProxySession) Close() error {
	var err error
	if s.cc != nil {
		err = s.cc.Close()
		s.cc = nil
	}
	if s.raw != nil {
		if closeErr := s.raw.Close(); err == nil {
			err = closeErr
		}
		s.raw = nil
	}
	return err
}

// h3ProxySession holds a single QUIC connection used for HTTP/3 CONNECT tunnels.
type h3ProxySession struct {
	conn      *quic.Conn
	udpConn   *net.UDPConn
	rt        *http3.Transport
	proxyHost string
	token     string
	timeout   time.Duration
}

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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	quicCfg := &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
	}

	perAttempt := timeout / time.Duration(len(ips))
	if perAttempt < 3*time.Second {
		perAttempt = 3 * time.Second
	}

	var (
		conn    *quic.Conn
		udpConn *net.UDPConn
		lastErr error
	)
	for _, ip := range ips {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			lastErr = err
			continue
		}
		udpAddr := &net.UDPAddr{IP: ip.AsSlice(), Port: port, Zone: ip.Zone()}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, perAttempt)
		c, err := quic.Dial(attemptCtx, uc, udpAddr, tlsCfg, quicCfg)
		attemptCancel()
		if err != nil {
			_ = uc.Close()
			lastErr = fmt.Errorf("dial %s: %w", udpAddr, err)
			continue
		}
		conn = c
		udpConn = uc
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
	logInfo("upstream HTTP/3 session established proxy=%s remote=%s", proxyHost, conn.RemoteAddr())

	rt := &http3.Transport{
		Dial: func(_ context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}

	return &h3ProxySession{
		conn:      conn,
		udpConn:   udpConn,
		rt:        rt,
		proxyHost: proxyHost,
		token:     token,
		timeout:   timeout,
	}, nil
}

func (s *h3ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	pr, pw := io.Pipe()
	resp, cancel, err := roundTripWithOpenTimeout(s.timeout, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+authority, pr)
		if err != nil {
			return nil, err
		}
		req.Host = authority
		req.URL.Host = s.proxyHost
		req.Header.Set("Proxy-Authorization", "Bearer "+s.token)
		return s.rt.RoundTrip(req)
	})
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, &proxyConnectHTTPError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
			body:       strings.TrimSpace(string(body)),
		}
	}

	return &tunnelConn{
		reader:  resp.Body,
		writer:  pw,
		reqBody: pr,
		name:    "h3-connect-stream",
		cancel:  cancel,
	}, nil
}

func (s *h3ProxySession) Close() error {
	if s.rt != nil {
		_ = s.rt.Close()
	}
	var err error
	if s.conn != nil {
		err = s.conn.CloseWithError(0, "")
	}
	if s.udpConn != nil {
		if closeErr := s.udpConn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

type tunnelConn struct {
	reader  io.ReadCloser
	writer  *io.PipeWriter
	reqBody *io.PipeReader
	cancel  context.CancelFunc
	name    tunnelAddr

	closeOnce sync.Once
	readOnce  sync.Once
	writeOnce sync.Once
	closeErr  error
	readErr   error
	writeErr  error
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *tunnelConn) Close() error {
	c.closeOnce.Do(func() {
		writeErr := c.CloseWrite()
		if c.reqBody != nil {
			_ = c.reqBody.Close()
		}
		readErr := c.CloseRead()
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
	expiresAt time.Time
	refs      int
	accepting bool
}

type proxyControllerConfig struct {
	Guardian string
	ProxyURL *url.URL
	Timeout  time.Duration
	Auth     *runtimeAuth
	Pass     *vpnclient.ProxyPassInfo
	UseH3    bool
}

type proxyController struct {
	guardian string
	proxyURL *url.URL
	timeout  time.Duration

	sessionFactory func(token string) (proxySession, error)
	refreshSession func() error

	renewMu sync.Mutex
	mu      sync.Mutex
	auth    *runtimeAuth
	current *managedSession
	closed  bool
}

func newProxyController(cfg proxyControllerConfig) (*proxyController, error) {
	var factory func(token string) (proxySession, error)
	if cfg.UseH3 {
		factory = func(token string) (proxySession, error) {
			return newH3ProxySession(cfg.ProxyURL, token, cfg.Timeout)
		}
	} else {
		factory = func(token string) (proxySession, error) {
			return newH2ProxySession(cfg.ProxyURL, token, cfg.Timeout)
		}
	}

	session, err := factory(cfg.Pass.RawToken)
	if err != nil {
		return nil, err
	}

	return &proxyController{
		guardian:       cfg.Guardian,
		proxyURL:       cfg.ProxyURL,
		timeout:        cfg.Timeout,
		sessionFactory: factory,
		auth:           cfg.Auth,
		current: &managedSession{
			session:   session,
			expiresAt: cfg.Pass.ExpiresAt(),
			accepting: true,
		},
	}, nil
}

func (c *proxyController) OpenTunnel(authority string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt <= maxOpenTunnelRebuildRetries; attempt++ {
		var failedSession *managedSession
		ms, release, err := c.acquireSession()
		if err != nil {
			if c.isClosed() {
				return nil, err
			}
			if !errors.Is(err, errNoUsableProxySession) || lastErr == nil {
				lastErr = err
			}
		} else {
			conn, err := ms.session.OpenTunnel(authority)
			if err == nil {
				return &managedTunnelConn{
					Conn:    conn,
					release: release,
				}, nil
			}
			if !shouldRebuildProxySession(err) {
				release()
				return nil, err
			}
			lastErr = err
			failedSession = ms
			c.markSessionUnusable(ms)
			release()
		}

		if attempt == maxOpenTunnelRebuildRetries {
			break
		}

		logWarn("upstream tunnel open failed; rebuilding proxy session attempt=%d max=%d err=%s", attempt+1, maxOpenTunnelRebuildRetries, logErr(lastErr))
		if err := c.rebuildSession(failedSession); err != nil {
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

	ms := c.current
	ms.refs++
	return ms, func() { c.releaseSession(ms) }, nil
}

func (c *proxyController) releaseSession(ms *managedSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ms.refs--
	c.maybeCloseLocked(ms)
}

func (c *proxyController) markSessionUnusable(ms *managedSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ms == nil || c.current != ms {
		return
	}
	ms.accepting = false
	c.maybeCloseLocked(ms)
}

func (c *proxyController) maybeCloseLocked(ms *managedSession) {
	if ms == nil || ms.accepting || ms.refs > 0 || ms.session == nil {
		return
	}
	_ = ms.session.Close()
	ms.session = nil
}

func (c *proxyController) swapSession(newSession proxySession, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	old := c.current
	c.current = &managedSession{
		session:   newSession,
		expiresAt: expiresAt,
		accepting: true,
	}
	if old != nil {
		old.accepting = false
		c.maybeCloseLocked(old)
	}
}

func (c *proxyController) disableExpiredSession(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.current != nil && c.current.accepting && !now.Before(c.current.expiresAt) {
		c.current.accepting = false
		c.maybeCloseLocked(c.current)
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
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return
		}
		sleep := c.nextRenewalDelay()
		if sleep > 0 {
			time.Sleep(sleep)
		}
		if err := c.renew(); err != nil {
			now := time.Now()
			logWarn("proxy pass renewal failed: %s", logErr(err))
			c.disableExpiredSession(now)
			logDebug("proxy pass renewal retry scheduled delay=%s", proxyPassRetryDelay)
			time.Sleep(proxyPassRetryDelay)
			continue
		}
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
		logDebug("skipping proxy session rebuild: another usable session is already active")
		return nil
	}
	if c.refreshSession != nil {
		return c.refreshSession()
	}
	return c.renewLocked()
}

func (c *proxyController) renewLocked() error {
	auth, err := c.ensureOAuthToken()
	if err != nil {
		return err
	}

	pass, err := vpnclient.FetchProxyPass(c.guardian, auth.Token.AccessToken)
	if err != nil {
		var guardianErr *vpnclient.GuardianHTTPError
		if !errors.As(err, &guardianErr) || guardianErr.StatusCode != http.StatusForbidden {
			return err
		}
		logInfo("Guardian account requires activation during proxy pass renewal; activating")
		if _, activateErr := vpnclient.ActivateGuardian(c.guardian, auth.Token.AccessToken); activateErr != nil {
			return activateErr
		}
		logInfo("Guardian account activated during proxy pass renewal")
		pass, err = vpnclient.FetchProxyPass(c.guardian, auth.Token.AccessToken)
		if err != nil {
			return err
		}
	}

	session, err := c.sessionFactory(pass.RawToken)
	if err != nil {
		return err
	}

	c.swapSession(session, pass.ExpiresAt())
	logInfo("proxy pass renewed successfully next_expiry=%s", pass.ExpiresAt().Format(time.RFC3339))
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
		return nil, fmt.Errorf("no refresh token available for background renewal")
	}

	logInfo("refreshing OAuth token")
	token, err := vpnclient.FxaRefreshToken(auth.Token.RefreshToken)
	if err != nil {
		return nil, err
	}

	refreshed := &runtimeAuth{
		Token:      token,
		ObtainedAt: now,
	}
	if err := vpnclient.SaveTokens(token); err != nil {
		logWarn("saving refreshed tokens failed: %v", err)
	}

	c.mu.Lock()
	c.auth = refreshed
	c.mu.Unlock()
	logInfo("OAuth token refreshed")
	return refreshed, nil
}

func (c *proxyController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	var err error
	if c.current != nil && c.current.session != nil {
		err = c.current.session.Close()
		c.current.session = nil
	}
	return err
}

type managedTunnelConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *managedTunnelConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		if c.release != nil {
			c.release()
		}
	})
	return err
}
