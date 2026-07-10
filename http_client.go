package vpnclient

import (
	"io"
	"net/http"
	"time"
)

const (
	controlPlaneHTTPTimeout = 30 * time.Second
	errorBodyLogLimit       = 16 * 1024
)

var controlPlaneHTTPClient = &http.Client{
	Timeout: controlPlaneHTTPTimeout,
}

func doControlPlane(req *http.Request) (*http.Response, error) {
	return controlPlaneHTTPClient.Do(req)
}

func getControlPlane(rawURL string) (*http.Response, error) {
	return controlPlaneHTTPClient.Get(rawURL)
}

func readErrorBody(r io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(r, errorBodyLogLimit))
	if err != nil {
		return "reading error body failed: " + err.Error()
	}
	return string(body)
}
