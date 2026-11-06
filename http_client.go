package vpnclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	controlPlaneHTTPTimeout = 30 * time.Second
	errorBodyLogLimit       = 16 * 1024

	// controlPlaneDialTimeout bounds TCP connect and the uTLS handshake for
	// direct control plane connections.
	controlPlaneDialTimeout = 15 * time.Second
)

// NewControlPlaneTransport builds the HTTP/2 transport used for all control
// plane requests (FxA, Guardian, Remote Settings).
//
// Since early November 2026 the Fastly edge in front of
// api.accounts.firefox.com applies strict bot defenses to oauth/token
// requests that ask for the VPN scope, keying on the TLS ClientHello
// fingerprint: Go's crypto/tls ClientHello is a well-known bot signature and
// gets HTTP 406 regardless of User-Agent, cookies, or HTTP version. Direct
// connections therefore present a Firefox ClientHello via uTLS, matching the
// pinned Firefox User-Agent. On top of that hello the edge again accepts
// HTTP/2, so the control plane rides http2.Transport over the uTLS dialer.
//
// The uTLS handshake covers direct connections only. With -api-proxy
// configured, net/http performs TLS itself over the proxied socket using
// Go's ClientHello; if that path ever gets blocked, routing -api-proxy
// through a fixed-exit HTTPS proxy is the workaround.
func NewControlPlaneTransport() *http2.Transport {
	return &http2.Transport{
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialFirefoxTLS(context.Background(), network, addr)
		},
	}
}

// dialFirefoxTLS dials addr and completes a TLS handshake with a Firefox
// ClientHello. The Firefox presets offer ALPN h2 and http/1.1; the edge
// negotiates h2, which the http2.Transport on top speaks natively.
func dialFirefoxTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("control plane address %q: %w", addr, err)
	}
	rawConn, err := (&net.Dialer{Timeout: controlPlaneDialTimeout}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
		MinVersion: utls.VersionTLS12,
	}, utls.HelloFirefox_Auto)
	handshakeCtx, cancel := context.WithTimeout(ctx, controlPlaneDialTimeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// controlPlaneHTTPClient is the isolated HTTP client for all API requests
// (FxA, Guardian, Remote Settings). It carries an explicit timeout so
// requests can never hang indefinitely; SetControlPlaneTransport may replace
// its Transport. It is deliberately kept separate from http.DefaultClient.
// The cookie jar holds Fastly anti-bot challenge cookies earned by
// solveFastlyChallenge.
var controlPlaneHTTPClient = func() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(fmt.Sprintf("creating control plane cookie jar: %v", err))
	}
	return &http.Client{
		Timeout:   controlPlaneHTTPTimeout,
		Jar:       jar,
		Transport: NewControlPlaneTransport(),
	}
}()

// SetControlPlaneTransport routes Firefox Accounts, Guardian, and Remote
// Settings requests through transport. It must be called before any control
// plane request is issued, because the client is shared process-wide.
// Transports built with NewControlPlaneTransport keep the Firefox
// ClientHello.
func SetControlPlaneTransport(transport http.RoundTripper) {
	controlPlaneHTTPClient.Transport = transport
}

func doControlPlane(req *http.Request) (*http.Response, error) {
	return controlPlaneHTTPClient.Do(req)
}

func readErrorBody(r io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(r, errorBodyLogLimit))
	if err != nil {
		return "reading error body failed: " + err.Error()
	}
	return string(body)
}
