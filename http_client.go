package vpnclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

const (
	controlPlaneHTTPTimeout = 30 * time.Second
	errorBodyLogLimit       = 16 * 1024
)

// NewControlPlaneTransport builds the HTTP transport used for all control
// plane requests (FxA, Guardian, Remote Settings). It is pinned to HTTP/1.1:
// since November 2026 the Fastly edge in front of api.accounts.firefox.com
// rejects requests whose HTTP/2 client fingerprint matches Go's
// x/net/http2 defaults (HTTP 406 regardless of User-Agent and cookies),
// while the same Go TLS stack over HTTP/1.1 passes. Control plane traffic is
// small sequential JSON, so losing HTTP/2 multiplexing costs nothing.
func NewControlPlaneTransport() *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		// A non-nil empty map stops net/http from installing its own h2
		// transport even if some other code re-enables ForceAttemptHTTP2.
		TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	}
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
// Transports built with NewControlPlaneTransport keep the HTTP/1.1 pin.
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
