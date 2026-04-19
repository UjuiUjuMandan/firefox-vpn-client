package main

import (
	"bufio"
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
	"strings"
	"sync"
	"time"

	vpnclient "firefox-vpn-client"
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
	proxyPassRenewLead  = 2 * time.Minute
	proxyPassRetryDelay = 30 * time.Second
	oauthRefreshLead    = 2 * time.Minute
)

var (
	errProxyHTTP2Unavailable = errors.New("proxy did not negotiate HTTP/2")
	errNoUsableProxySession  = errors.New("no usable upstream proxy session")
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "Usage of proxy-demo:")
		fmt.Fprintln(out, "  proxy-demo [-proxy https://HOST:PORT] [-listen 127.0.0.1:1080] [-print-info]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "This program logs in to Firefox Accounts, fetches a VPN proxy pass, and")
		fmt.Fprintln(out, "exposes a local SOCKS5 CONNECT proxy over a single upstream HTTP/2 connection.")
		fmt.Fprintln(out)
		flag.PrintDefaults()
	}

	guardianFlag := flag.String("guardian", vpnclient.GuardianEndpointDefault, "Guardian API endpoint")
	listenFlag := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	loginFlag := flag.Bool("login", false, "Force fresh login (ignore saved refresh token)")
	printInfoFlag := flag.Bool("print-info", false, "Print user info, quota info, and server list, then exit")
	proxyFlag := flag.String("proxy", "", "Upstream proxy URL or host:port; random CONNECT server if omitted")
	timeoutFlag := flag.Duration("timeout", 20*time.Second, "Upstream dial and handshake timeout")
	flag.Parse()

	runtimeAuth, tokenSource, countries := prepareDemoInputs(
		*loginFlag,
		strings.TrimSpace(*proxyFlag) == "",
	)

	selectedProxy, err := resolveProxy(strings.TrimSpace(*proxyFlag), countries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error selecting proxy: %v\n", err)
		os.Exit(1)
	}

	proxyURL, err := normalizeProxyURL(selectedProxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid proxy: %v\n", err)
		os.Exit(1)
	}

	pass, err := vpnclient.FetchProxyPass(*guardianFlag, runtimeAuth.Token.AccessToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching proxy pass: %v\n", err)
		os.Exit(1)
	}
	if *printInfoFlag {
		printRuntimeInfo(*guardianFlag, runtimeAuth.Token.AccessToken, pass, countries)
		return
	}
	controller, err := newProxyController(proxyControllerConfig{
		Guardian: *guardianFlag,
		ProxyURL: proxyURL,
		Timeout:  *timeoutFlag,
		Auth:     runtimeAuth,
		Pass:     pass,
	})
	if err != nil {
		if errors.Is(err, errProxyHTTP2Unavailable) {
			fmt.Fprintln(os.Stderr, "Error: upstream proxy does not support HTTP/2; refusing to start because this server must use a single upstream TCP connection.")
		} else {
			fmt.Fprintf(os.Stderr, "Error: could not establish upstream HTTP/2 proxy session: %v\n", err)
		}
		os.Exit(1)
	}
	defer controller.Close()
	go controller.runRenewalLoop()

	ln, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", *listenFlag, err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Printf("SOCKS5 listen:  %s\n", ln.Addr().String())
	fmt.Printf("Upstream proxy: %s\n", selectedProxy)
	fmt.Printf("Auth source:    %s\n", tokenSource)
	fmt.Printf("Proxy pass exp: %s\n", pass.ExpiresAt().Format(time.RFC3339))
	fmt.Printf("Transport:      single upstream HTTP/2 TCP connection with background proxy-pass renewal\n")

	server := &socksServer{
		upstream: controller,
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}
		go server.handleConn(conn)
	}
}

func prepareDemoInputs(forceLogin, needServerList bool) (*runtimeAuth, string, []vpnclient.Country) {
	token, tokenSource := obtainOAuthToken(forceLogin)

	if err := vpnclient.SaveTokens(token); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save tokens: %v\n", err)
	}

	var countries []vpnclient.Country
	var err error
	if needServerList {
		countries, err = vpnclient.FetchServerList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch server list: %v\n", err)
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
				fmt.Fprintln(os.Stderr, "Saved tokens were preserved. Retry by restarting the program, or use -login to force a fresh login.")
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
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(email), string(passwordBytes)
}

func resolveProxy(proxyFlag string, countries []vpnclient.Country) (string, error) {
	if proxyFlag != "" {
		return proxyFlag, nil
	}

	proxies := connectProxyHosts(countries)
	if len(proxies) == 0 {
		return "", fmt.Errorf("no CONNECT proxies available from server list; pass -proxy explicitly")
	}
	return proxies[rand.IntN(len(proxies))], nil
}

func connectProxyHosts(countries []vpnclient.Country) []string {
	var proxies []string
	for _, country := range countries {
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				if len(srv.Protocols) == 0 && srv.Hostname != "" && srv.Port > 0 {
					proxies = append(proxies, fmt.Sprintf("%s:%d", srv.Hostname, srv.Port))
					continue
				}
				for _, proto := range srv.Protocols {
					if proto.Name == "connect" && proto.Host != "" && proto.Port > 0 {
						proxies = append(proxies, fmt.Sprintf("%s:%d", proto.Host, proto.Port))
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
	upstream tunnelOpener
}

func (s *socksServer) handleConn(conn net.Conn) {
	defer conn.Close()

	target, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		if replyCode != 0 {
			_ = writeSOCKSReply(conn, replyCode, nil)
		}
		return
	}

	upstreamConn, err := s.upstream.OpenTunnel(target)
	if err != nil {
		_ = writeSOCKSReply(conn, mapUpstreamError(err), nil)
		return
	}
	defer upstreamConn.Close()

	if err := writeSOCKSReply(conn, socksReplySuccess, conn.LocalAddr()); err != nil {
		return
	}

	proxyBidirectional(conn, upstreamConn)
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

	return &h2ProxySession{
		raw:       proxyTLS,
		cc:        cc,
		proxyHost: proxyHost,
		token:     token,
	}, nil
}

func (s *h2ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "http://"+authority, pr)
	if err != nil {
		return nil, err
	}
	req.Host = authority
	req.URL.Host = s.proxyHost
	req.Header.Set("Proxy-Authorization", "Bearer "+s.token)

	resp, err := s.cc.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return &tunnelConn{
		reader:  resp.Body,
		writer:  pw,
		reqBody: pr,
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

type tunnelConn struct {
	reader  io.ReadCloser
	writer  *io.PipeWriter
	reqBody *io.PipeReader

	closeOnce sync.Once
	closeErr  error
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *tunnelConn) Close() error {
	c.closeOnce.Do(func() {
		if c.writer != nil {
			_ = c.writer.Close()
		}
		if c.reqBody != nil {
			_ = c.reqBody.Close()
		}
		if c.reader != nil {
			c.closeErr = c.reader.Close()
		}
	})
	return c.closeErr
}

func (c *tunnelConn) LocalAddr() net.Addr              { return tunnelAddr("h2-connect-stream") }
func (c *tunnelConn) RemoteAddr() net.Addr             { return tunnelAddr("h2-connect-stream") }
func (c *tunnelConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

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
}

type proxyController struct {
	guardian string
	proxyURL *url.URL
	timeout  time.Duration

	sessionFactory func(token string) (proxySession, error)

	mu      sync.Mutex
	auth    *runtimeAuth
	current *managedSession
	closed  bool
}

func newProxyController(cfg proxyControllerConfig) (*proxyController, error) {
	session, err := newH2ProxySession(cfg.ProxyURL, cfg.Pass.RawToken, cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return &proxyController{
		guardian: cfg.Guardian,
		proxyURL: cfg.ProxyURL,
		timeout:  cfg.Timeout,
		sessionFactory: func(token string) (proxySession, error) {
			return newH2ProxySession(cfg.ProxyURL, token, cfg.Timeout)
		},
		auth: cfg.Auth,
		current: &managedSession{
			session:   session,
			expiresAt: cfg.Pass.ExpiresAt(),
			accepting: true,
		},
	}, nil
}

func (c *proxyController) OpenTunnel(authority string) (net.Conn, error) {
	ms, release, err := c.acquireSession()
	if err != nil {
		return nil, err
	}

	conn, err := ms.session.OpenTunnel(authority)
	if err != nil {
		release()
		return nil, err
	}
	return &managedTunnelConn{
		Conn:    conn,
		release: release,
	}, nil
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
			fmt.Fprintf(os.Stderr, "Proxy pass renewal failed: %v\n", err)
			c.disableExpiredSession(now)
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
	auth, err := c.ensureOAuthToken()
	if err != nil {
		return err
	}

	pass, err := vpnclient.FetchProxyPass(c.guardian, auth.Token.AccessToken)
	if err != nil {
		return err
	}

	session, err := c.sessionFactory(pass.RawToken)
	if err != nil {
		return err
	}

	c.swapSession(session, pass.ExpiresAt())
	fmt.Fprintf(os.Stderr, "Proxy pass renewed successfully; next expiry %s\n", pass.ExpiresAt().Format(time.RFC3339))
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

	token, err := vpnclient.FxaRefreshToken(auth.Token.RefreshToken)
	if err != nil {
		return nil, err
	}

	refreshed := &runtimeAuth{
		Token:      token,
		ObtainedAt: now,
	}
	if err := vpnclient.SaveTokens(token); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save refreshed tokens: %v\n", err)
	}

	c.mu.Lock()
	c.auth = refreshed
	c.mu.Unlock()
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
