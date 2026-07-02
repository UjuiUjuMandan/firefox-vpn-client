package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vpnclient "firefox-vpn-client"
)

func TestNormalizeProxyURLAddsHTTPS(t *testing.T) {
	t.Parallel()

	got, err := normalizeProxyURL("proxy.example.test:443")
	if err != nil {
		t.Fatalf("normalizeProxyURL returned error: %v", err)
	}

	if got.Scheme != "https" {
		t.Fatalf("expected https scheme, got %q", got.Scheme)
	}
	if got.Host != "proxy.example.test:443" {
		t.Fatalf("expected host proxy.example.test:443, got %q", got.Host)
	}
}

func TestHandshakeSOCKS5DomainConnect(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte{socksVersion5, 0x01, socksAuthNoAuth})
		if err != nil {
			errCh <- err
			return
		}

		reply := make([]byte, 2)
		_, err = io.ReadFull(client, reply)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(reply, []byte{socksVersion5, socksAuthNoAuth}) {
			errCh <- errors.New("unexpected auth reply")
			return
		}
		_, err = client.Write([]byte{
			socksVersion5, socksCmdConnect, 0x00, socksAtypDomain, 0x0b,
			'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			0x01, 0xbb,
		})
		if err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	target, replyCode, err := handshakeSOCKS5(server)
	if err != nil {
		t.Fatalf("handshakeSOCKS5 returned error: %v", err)
	}
	if replyCode != socksReplySuccess {
		t.Fatalf("expected success code, got %d", replyCode)
	}
	if target != "example.com:443" {
		t.Fatalf("expected target example.com:443, got %q", target)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client goroutine failed: %v", err)
	}
}

func TestHandshakeSOCKS5RejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		if _, err := client.Write([]byte{socksVersion5, 0x01, 0x02}); err != nil {
			errCh <- err
			return
		}
		reply := make([]byte, 2)
		_, err := io.ReadFull(client, reply)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(reply, []byte{socksVersion5, socksAuthNoAccept}) {
			errCh <- errors.New("unexpected auth rejection reply")
			return
		}
		errCh <- nil
	}()

	_, _, err := handshakeSOCKS5(server)
	if err == nil || !strings.Contains(err.Error(), "no supported SOCKS auth methods") {
		t.Fatalf("expected unsupported auth error, got %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client goroutine failed: %v", err)
	}
}

func TestHandshakeSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte{socksVersion5, 0x01, socksAuthNoAuth})
		reply := make([]byte, 2)
		_, _ = io.ReadFull(client, reply)
		_, _ = client.Write([]byte{
			socksVersion5, 0x03, 0x00, socksAtypIPv4, 127, 0, 0, 1, 0x00, 0x50,
		})
	}()

	_, replyCode, err := handshakeSOCKS5(server)
	if err == nil {
		t.Fatal("expected unsupported command error")
	}
	if replyCode != socksReplyCmdUnsup {
		t.Fatalf("expected command unsupported reply code, got %d", replyCode)
	}
}

func TestConnectProxyHostsIncludesDefaultConnectServers(t *testing.T) {
	t.Parallel()

	countries := []vpnclient.Country{
		{
			Name: "United States",
			Code: "US",
			Cities: []vpnclient.City{
				{
					Name: "New York",
					Code: "nyc",
					Servers: []vpnclient.Server{
						{Hostname: "default.example", Port: 443},
						{Protocols: []vpnclient.Protocol{{Name: "connect", Host: "proto.example", Port: 8443}}},
					},
				},
			},
		},
	}

	got := connectProxyHosts(countries)
	want := []string{"default.example:443", "proto.example:8443"}
	if len(got) != len(want) {
		t.Fatalf("expected %d proxies, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %q at index %d, got %q", want[i], i, got[i])
		}
	}
}

func TestConnectProxyCandidatesIncludeExitMetadata(t *testing.T) {
	t.Parallel()

	countries := []vpnclient.Country{
		{
			Name: "Germany",
			Code: "DE",
			Cities: []vpnclient.City{
				{
					Name: "Frankfurt",
					Code: "fra",
					Servers: []vpnclient.Server{
						{Protocols: []vpnclient.Protocol{{Name: "connect", Host: "de.example", Port: 443}}},
					},
				},
			},
		},
	}

	got := connectProxyCandidates(countries)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %v", len(got), got)
	}
	candidate := got[0]
	if candidate.Addr != "de.example:443" {
		t.Fatalf("expected proxy de.example:443, got %q", candidate.Addr)
	}
	if candidate.CountryName != "Germany" || candidate.CountryCode != "DE" {
		t.Fatalf("unexpected country metadata: %#v", candidate)
	}
	if candidate.CityName != "Frankfurt" || candidate.CityCode != "fra" {
		t.Fatalf("unexpected city metadata: %#v", candidate)
	}
}

func TestResolveProxyMatchesExplicitProxyMetadata(t *testing.T) {
	t.Parallel()

	countries := []vpnclient.Country{
		{
			Name: "Japan",
			Code: "JP",
			Cities: []vpnclient.City{
				{
					Name: "Tokyo",
					Code: "tyo",
					Servers: []vpnclient.Server{
						{Hostname: "jp.example", Port: 443},
					},
				},
			},
		},
	}

	got, err := resolveProxy("https://jp.example", countries)
	if err != nil {
		t.Fatalf("resolveProxy returned error: %v", err)
	}
	if got.Addr != "https://jp.example" {
		t.Fatalf("expected original proxy flag to be preserved, got %q", got.Addr)
	}
	if got.CountryCode != "JP" || got.CityCode != "tyo" {
		t.Fatalf("expected explicit proxy metadata match, got %#v", got)
	}
}

type fakeTunnelOpener struct {
	active atomic.Int32
	max    atomic.Int32
	delay  time.Duration
}

func (f *fakeTunnelOpener) OpenTunnel(authority string) (net.Conn, error) {
	current := f.active.Add(1)
	for {
		max := f.max.Load()
		if current <= max || f.max.CompareAndSwap(max, current) {
			break
		}
	}

	left, right := net.Pipe()
	go func() {
		time.Sleep(f.delay)
		f.active.Add(-1)
		_ = right.Close()
	}()
	return left, nil
}

func TestSocksServerAllowsConcurrentClients(t *testing.T) {
	t.Parallel()

	server := &socksServer{upstream: &fakeTunnelOpener{delay: 50 * time.Millisecond}}

	runClient := func() error {
		client, conn := net.Pipe()
		defer client.Close()

		done := make(chan struct{})
		go func() {
			server.handleConn(conn)
			close(done)
		}()

		if _, err := client.Write([]byte{socksVersion5, 0x01, socksAuthNoAuth}); err != nil {
			return err
		}

		reply := make([]byte, 12)
		if _, err := io.ReadFull(client, reply[:2]); err != nil {
			return err
		}
		if !bytes.Equal(reply[:2], []byte{socksVersion5, socksAuthNoAuth}) {
			return errors.New("unexpected auth reply")
		}
		if _, err := client.Write([]byte{
			socksVersion5, socksCmdConnect, 0x00, socksAtypDomain, 0x0b,
			'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			0x01, 0xbb,
		}); err != nil {
			return err
		}
		if _, err := io.ReadFull(client, reply[:10]); err != nil {
			return err
		}
		if reply[1] != socksReplySuccess {
			return errors.New("unexpected connect reply")
		}

		_ = client.Close()
		<-done
		return nil
	}

	errCh := make(chan error, 2)
	go func() { errCh <- runClient() }()
	go func() { errCh <- runClient() }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client %d failed: %v", i, err)
		}
	}

	opener := server.upstream.(*fakeTunnelOpener)
	if opener.max.Load() < 2 {
		t.Fatalf("expected concurrent tunnel opens, max=%d", opener.max.Load())
	}
}

func TestSocksServerRejectsWhenConnectionLimitReached(t *testing.T) {
	t.Parallel()

	server := &socksServer{connSlots: make(chan struct{}, 1)}
	server.connSlots <- struct{}{}

	client, conn := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		server.handleConn(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not reject connection at limit")
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected client side to observe closed connection")
	}
}

func TestSocksServerHandshakeTimeout(t *testing.T) {
	t.Parallel()

	server := &socksServer{handshakeTimeout: 20 * time.Millisecond}
	client, conn := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		server.handleConn(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not close idle handshake connection")
	}
}

type fakeProxySession struct {
	openCount  atomic.Int32
	closeCount atomic.Int32
	openErr    error
}

func (s *fakeProxySession) OpenTunnel(authority string) (net.Conn, error) {
	s.openCount.Add(1)
	if s.openErr != nil {
		return nil, s.openErr
	}
	return &fakeNetConn{}, nil
}

func (s *fakeProxySession) Close() error {
	s.closeCount.Add(1)
	return nil
}

type fakeNetConn struct{}

func (c *fakeNetConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (c *fakeNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fakeNetConn) Close() error                     { return nil }
func (c *fakeNetConn) LocalAddr() net.Addr              { return tunnelAddr("fake") }
func (c *fakeNetConn) RemoteAddr() net.Addr             { return tunnelAddr("fake") }
func (c *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

func TestTunnelConnCloseWriteClosesRequestBody(t *testing.T) {
	t.Parallel()

	reqBody, writer := io.Pipe()
	conn := &tunnelConn{
		reader:  io.NopCloser(strings.NewReader("")),
		writer:  writer,
		reqBody: reqBody,
		name:    "test-tunnel",
	}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite returned error: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := reqBody.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected request body EOF after CloseWrite, got %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestTunnelConnCloseCancelsRequestContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	conn := &tunnelConn{
		reader: io.NopCloser(strings.NewReader("")),
		writer: func() *io.PipeWriter {
			_, writer := io.Pipe()
			return writer
		}(),
		cancel: cancel,
		name:   "test-tunnel",
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected Close to cancel request context")
	}
}

func TestTunnelConnDeadlineUnsupported(t *testing.T) {
	t.Parallel()

	conn := &tunnelConn{}
	if !errors.Is(conn.SetDeadline(time.Now()), errTunnelDeadline) {
		t.Fatal("expected SetDeadline to report unsupported tunnel deadline")
	}
	if !errors.Is(conn.SetReadDeadline(time.Now()), errTunnelDeadline) {
		t.Fatal("expected SetReadDeadline to report unsupported tunnel deadline")
	}
	if !errors.Is(conn.SetWriteDeadline(time.Now()), errTunnelDeadline) {
		t.Fatal("expected SetWriteDeadline to report unsupported tunnel deadline")
	}
}

func TestRoundTripWithOpenTimeout(t *testing.T) {
	t.Parallel()

	_, _, err := roundTripWithOpenTimeout(20*time.Millisecond, func(ctx context.Context) (*http.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	var timeoutErr *tunnelOpenTimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("expected tunnelOpenTimeoutError, got %v", err)
	}
}

func TestShouldRebuildProxySession(t *testing.T) {
	t.Parallel()

	if shouldRebuildProxySession(&proxyConnectHTTPError{statusCode: http.StatusBadGateway, status: "502 Bad Gateway"}) {
		t.Fatal("expected target/proxy CONNECT 502 to avoid session rebuild")
	}
	if !shouldRebuildProxySession(&proxyConnectHTTPError{statusCode: http.StatusProxyAuthRequired, status: "407 Proxy Authentication Required"}) {
		t.Fatal("expected proxy auth failure to rebuild session")
	}
	if shouldRebuildProxySession(&tunnelOpenTimeoutError{timeout: time.Second}) {
		t.Fatal("expected CONNECT timeout to avoid session rebuild")
	}
	if !shouldRebuildProxySession(errors.New("transport closed")) {
		t.Fatal("expected transport errors to rebuild session")
	}
}

func TestLogErrRedactsConnectHTTPBodyUnlessVerbose(t *testing.T) {
	previous := verboseLogs
	t.Cleanup(func() { verboseLogs = previous })

	err := &proxyConnectHTTPError{
		statusCode: http.StatusBadGateway,
		status:     "502 Bad Gateway",
		body:       "target example.com failed",
	}

	verboseLogs = false
	if got := logErr(err); strings.Contains(got, "example.com") {
		t.Fatalf("expected default log error to redact CONNECT body, got %q", got)
	}

	verboseLogs = true
	if got := logErr(err); !strings.Contains(got, "example.com") {
		t.Fatalf("expected verbose log error to keep CONNECT body, got %q", got)
	}
}

func TestProxyControllerSwapDrainsOldSession(t *testing.T) {
	t.Parallel()

	oldSession := &fakeProxySession{}
	newSession := &fakeProxySession{}
	controller := &proxyController{
		current: &managedSession{
			session:   oldSession,
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}

	conn1, err := controller.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel old session failed: %v", err)
	}
	if oldSession.openCount.Load() != 1 {
		t.Fatalf("expected old session open count 1, got %d", oldSession.openCount.Load())
	}

	controller.swapSession(newSession, time.Now().Add(20*time.Minute))

	conn2, err := controller.OpenTunnel("example.org:443")
	if err != nil {
		t.Fatalf("OpenTunnel new session failed: %v", err)
	}
	if newSession.openCount.Load() != 1 {
		t.Fatalf("expected new session open count 1, got %d", newSession.openCount.Load())
	}
	if oldSession.closeCount.Load() != 0 {
		t.Fatalf("old session closed too early: %d", oldSession.closeCount.Load())
	}

	_ = conn2.Close()
	if newSession.closeCount.Load() != 0 {
		t.Fatalf("new current session should remain open, got close count %d", newSession.closeCount.Load())
	}

	_ = conn1.Close()
	if oldSession.closeCount.Load() != 1 {
		t.Fatalf("expected old session to close after draining, got %d", oldSession.closeCount.Load())
	}
}

func TestProxyControllerDisableExpiredSessionRejectsNewTunnels(t *testing.T) {
	t.Parallel()

	session := &fakeProxySession{}
	controller := &proxyController{
		current: &managedSession{
			session:   session,
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	controller.refreshSession = func() error {
		return errNoUsableProxySession
	}

	conn, err := controller.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel failed: %v", err)
	}

	controller.disableExpiredSession(time.Now().Add(11 * time.Minute))

	_, err = controller.OpenTunnel("example.org:443")
	if !errors.Is(err, errNoUsableProxySession) {
		t.Fatalf("expected errNoUsableProxySession, got %v", err)
	}
	if session.closeCount.Load() != 0 {
		t.Fatalf("session closed while active tunnel exists: %d", session.closeCount.Load())
	}

	_ = conn.Close()
	if session.closeCount.Load() != 1 {
		t.Fatalf("expected session close after active tunnel drained, got %d", session.closeCount.Load())
	}
}

func TestProxyControllerRebuildsSessionAfterOpenTunnelFailure(t *testing.T) {
	t.Parallel()

	failedSession := &fakeProxySession{openErr: errors.New("upstream session is gone")}
	newSession := &fakeProxySession{}
	controller := &proxyController{
		current: &managedSession{
			session:   failedSession,
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	controller.refreshSession = func() error {
		controller.swapSession(newSession, time.Now().Add(20*time.Minute))
		return nil
	}

	conn, err := controller.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel after rebuild failed: %v", err)
	}
	_ = conn.Close()

	if failedSession.openCount.Load() != 1 {
		t.Fatalf("expected failed session open count 1, got %d", failedSession.openCount.Load())
	}
	if failedSession.closeCount.Load() != 1 {
		t.Fatalf("expected failed session to close after rebuild, got %d", failedSession.closeCount.Load())
	}
	if newSession.openCount.Load() != 1 {
		t.Fatalf("expected new session open count 1, got %d", newSession.openCount.Load())
	}
}

func TestProxyControllerDoesNotRebuildForConnectHTTPFailure(t *testing.T) {
	t.Parallel()

	session := &fakeProxySession{
		openErr: &proxyConnectHTTPError{
			statusCode: http.StatusBadGateway,
			status:     "502 Bad Gateway",
			body:       "target unreachable",
		},
	}
	controller := &proxyController{
		current: &managedSession{
			session:   session,
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	var rebuilds atomic.Int32
	controller.refreshSession = func() error {
		rebuilds.Add(1)
		return nil
	}

	_, err := controller.OpenTunnel("example.com:443")
	if err == nil {
		t.Fatal("expected OpenTunnel to fail")
	}
	var connectErr *proxyConnectHTTPError
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected proxyConnectHTTPError, got %v", err)
	}
	if rebuilds.Load() != 0 {
		t.Fatalf("expected no rebuilds, got %d", rebuilds.Load())
	}
	if session.closeCount.Load() != 0 {
		t.Fatalf("expected current session to remain open, got close count %d", session.closeCount.Load())
	}
	if !controller.current.accepting {
		t.Fatal("expected current session to remain accepting")
	}
}

func TestProxyControllerStopsAfterThreeOpenTunnelRebuilds(t *testing.T) {
	t.Parallel()

	controller := &proxyController{
		current: &managedSession{
			session:   &fakeProxySession{openErr: errors.New("initial session failed")},
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	var rebuilds atomic.Int32
	controller.refreshSession = func() error {
		n := rebuilds.Add(1)
		controller.swapSession(
			&fakeProxySession{openErr: fmt.Errorf("rebuilt session %d failed", n)},
			time.Now().Add(20*time.Minute),
		)
		return nil
	}

	_, err := controller.OpenTunnel("example.com:443")
	if err == nil {
		t.Fatal("expected OpenTunnel to fail")
	}
	if rebuilds.Load() != maxOpenTunnelRebuildRetries {
		t.Fatalf("expected %d rebuilds, got %d", maxOpenTunnelRebuildRetries, rebuilds.Load())
	}
}

func TestProxyControllerKeepsRebuildErrorWhenSessionUnavailable(t *testing.T) {
	t.Parallel()

	controller := &proxyController{
		current: &managedSession{
			session:   &fakeProxySession{openErr: errors.New("initial session failed")},
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	var rebuilds atomic.Int32
	controller.refreshSession = func() error {
		rebuilds.Add(1)
		return errors.New("refresh token rejected")
	}

	_, err := controller.OpenTunnel("example.com:443")
	if err == nil {
		t.Fatal("expected OpenTunnel to fail")
	}
	if !strings.Contains(err.Error(), "refresh token rejected") {
		t.Fatalf("expected rebuild error to be preserved, got %v", err)
	}
	if rebuilds.Load() != maxOpenTunnelRebuildRetries {
		t.Fatalf("expected %d rebuilds, got %d", maxOpenTunnelRebuildRetries, rebuilds.Load())
	}
}

func TestProxyControllerSkipsRebuildWhenSessionAlreadyReplaced(t *testing.T) {
	t.Parallel()

	oldSession := &fakeProxySession{}
	newSession := &fakeProxySession{}
	controller := &proxyController{
		current: &managedSession{
			session:   oldSession,
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}
	failed := controller.current
	controller.swapSession(newSession, time.Now().Add(20*time.Minute))

	var rebuilds atomic.Int32
	controller.refreshSession = func() error {
		rebuilds.Add(1)
		return nil
	}

	if err := controller.rebuildSession(failed); err != nil {
		t.Fatalf("rebuildSession returned error: %v", err)
	}
	if rebuilds.Load() != 0 {
		t.Fatalf("expected rebuild to be skipped, got %d rebuilds", rebuilds.Load())
	}
}
