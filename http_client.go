package vpnclient

import (
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

// controlPlaneHTTPClient is the isolated HTTP client for all API requests
// (FxA, Guardian, Remote Settings). It carries an explicit timeout so
// requests can never hang indefinitely; SetControlPlaneTransport may replace
// its Transport. It is deliberately kept separate from http.DefaultClient.
// The cookie jar holds Fastly anti-bot challenge cookies earned by
// solveFastlyChallenge.
//
//nolint:gochecknoglobals // shared process-wide client by design; see the doc comment above
var controlPlaneHTTPClient = func() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(fmt.Sprintf("creating control plane cookie jar: %v", err))
	}

	return &http.Client{
		Timeout: controlPlaneHTTPTimeout,
		Jar:     jar,
	}
}()

// SetControlPlaneTransport routes Firefox Accounts, Guardian, and Remote
// Settings requests through transport. It must be called before any control
// plane request is issued, because the client is shared process-wide.
func SetControlPlaneTransport(transport http.RoundTripper) {
	controlPlaneHTTPClient.Transport = transport
}

func doControlPlane(req *http.Request) (*http.Response, error) {
	resp, err := controlPlaneHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control plane request to %s: %w", req.URL.Host, err)
	}

	return resp, nil
}

func readErrorBody(r io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(r, errorBodyLogLimit))
	if err != nil {
		return "reading error body failed: " + err.Error()
	}

	return string(body)
}
