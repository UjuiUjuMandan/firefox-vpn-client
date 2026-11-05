package vpnclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestControlPlaneTransportPinsHTTP1 guards the HTTP/1.1 pin: Go's default
// HTTP/2 client fingerprint has been rejected by the Fastly edge with HTTP
// 406 since November 2026, so the control plane must never negotiate h2.
func TestControlPlaneTransportPinsHTTP1(t *testing.T) {
	t.Parallel()

	transport := NewControlPlaneTransport()
	if transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 must be false on the control plane transport")
	}
	if len(transport.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto must be empty, got %v", transport.TLSNextProto)
	}
	if got := transport.TLSClientConfig.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("ALPN must offer only http/1.1, got %v", got)
	}
}

func TestControlPlaneRequestsSpeakHTTP1OverTLS(t *testing.T) {
	previousTransport := controlPlaneHTTPClient.Transport
	t.Cleanup(func() { controlPlaneHTTPClient.Transport = previousTransport })

	protoMajor := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoMajor = r.ProtoMajor
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewControlPlaneTransport()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	controlPlaneHTTPClient.Transport = transport

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doControlPlane(req)
	if err != nil {
		t.Fatalf("control plane request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if protoMajor != 1 {
		t.Fatalf("control plane negotiated HTTP/%d, want HTTP/1.x", protoMajor)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("response was HTTP/%d, want HTTP/1.x", resp.ProtoMajor)
	}
}
