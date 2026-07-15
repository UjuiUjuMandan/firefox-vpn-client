package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestObtainOAuthTokenUsesValidCachedAccessToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	want := &vpnclient.TokenResponse{
		AccessToken:  "cached-access-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
		Scope:        "profile",
	}
	if err := vpnclient.SaveTokens(want); err != nil {
		t.Fatalf("SaveTokens returned error: %v", err)
	}

	got, source, obtainedAt := obtainOAuthToken(false)
	if source != "cached access token" {
		t.Fatalf("expected cached access token source, got %q", source)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("expected cached token %#v, got %#v", want, got)
	}
	if time.Since(obtainedAt) > time.Minute {
		t.Fatalf("expected cached obtained time to be preserved, got %s", obtainedAt)
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

func TestSelectProxyCandidateRequiresExplicitCountry(t *testing.T) {
	t.Parallel()

	countries := []vpnclient.Country{
		{
			Name: "United States",
			Code: "US",
			Cities: []vpnclient.City{{
				Name:    "United States",
				Code:    "US",
				Servers: []vpnclient.Server{{Hostname: "us.example", Port: 443}},
			}},
		},
		{
			Name: "France",
			Code: "FR",
			Cities: []vpnclient.City{{
				Name:    "France",
				Code:    "LFPB",
				Servers: []vpnclient.Server{{Hostname: "fr.example", Port: 443}},
			}},
		},
	}

	_, err := selectProxyCandidate(countries, "")
	if err == nil || !strings.Contains(err.Error(), "multiple VPN countries") {
		t.Fatalf("expected explicit-country error, got %v", err)
	}
}

func TestSelectProxyCandidateFiltersCountryDeterministically(t *testing.T) {
	t.Parallel()

	countries := []vpnclient.Country{
		{
			Name: "United States",
			Code: "US",
			Cities: []vpnclient.City{{
				Name: "United States",
				Code: "US",
				Servers: []vpnclient.Server{
					{Hostname: "us-primary.example", Port: 443},
					{Hostname: "us-secondary.example", Port: 443},
				},
			}},
		},
		{
			Name: "France",
			Code: "FR",
			Cities: []vpnclient.City{{
				Name:    "France",
				Code:    "LFPB",
				Servers: []vpnclient.Server{{Hostname: "fr.example", Port: 443}},
			}},
		},
	}

	for _, filter := range []string{"US", "united states"} {
		got, err := selectProxyCandidate(countries, filter)
		if err != nil {
			t.Fatalf("selectProxyCandidate(%q) returned error: %v", filter, err)
		}
		if got.Addr != "us-primary.example:443" {
			t.Fatalf("expected deterministic first US proxy for %q, got %q", filter, got.Addr)
		}
	}
}

func TestResolveProxyReusesPersistedSelection(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy-selection.json")
	want := proxyCandidate{
		Addr:        "stable.example:443",
		CountryName: "United States",
		CountryCode: "US",
		CityName:    "San Jose",
		CityCode:    "SJC",
	}
	if err := saveProxySelection(path, want); err != nil {
		t.Fatalf("saveProxySelection returned error: %v", err)
	}

	got, fromState, err := resolveProxyWithState("", nil, path)
	if err != nil {
		t.Fatalf("resolveProxyWithState returned error: %v", err)
	}
	if !fromState {
		t.Fatal("expected persisted proxy selection to be reused")
	}
	if got != want {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
}

func TestResolveProxyReplacesSelectionMissingFromFreshServerList(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy-selection.json")
	if err := saveProxySelection(path, proxyCandidate{Addr: "stale.example:443"}); err != nil {
		t.Fatalf("saveProxySelection returned error: %v", err)
	}
	countries := []vpnclient.Country{{
		Name: "Japan",
		Code: "JP",
		Cities: []vpnclient.City{{
			Name: "Tokyo",
			Code: "TYO",
			Servers: []vpnclient.Server{{
				Hostname: "current.example",
				Port:     443,
			}},
		}},
	}}

	got, fromState, err := resolveProxyWithState("", countries, path)
	if err != nil {
		t.Fatalf("resolveProxyWithState returned error: %v", err)
	}
	if fromState {
		t.Fatal("expected stale persisted selection to be replaced")
	}
	if got.Addr != "current.example:443" {
		t.Fatalf("expected current server-list proxy, got %q", got.Addr)
	}
}

func TestResolveProxyReplacesPersistedSelectionForConfiguredCountry(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy-selection.json")
	if err := saveProxySelection(path, proxyCandidate{
		Addr:        "us.example:443",
		CountryName: "United States",
		CountryCode: "US",
	}); err != nil {
		t.Fatalf("saveProxySelection returned error: %v", err)
	}
	countries := []vpnclient.Country{{
		Name: "France",
		Code: "FR",
		Cities: []vpnclient.City{{
			Name:    "France",
			Code:    "LFPB",
			Servers: []vpnclient.Server{{Hostname: "fr.example", Port: 443}},
		}},
	}}

	got, fromState, err := resolveProxyWithStateAndCountry("", "FR", countries, path)
	if err != nil {
		t.Fatalf("resolveProxyWithStateAndCountry returned error: %v", err)
	}
	if fromState {
		t.Fatal("expected configured country to replace mismatched persisted selection")
	}
	if got.Addr != "fr.example:443" || got.CountryCode != "FR" {
		t.Fatalf("expected French proxy, got %#v", got)
	}
}

func TestParseExitProbeResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantIP      string
		wantCountry string
	}{
		{
			name:        "cloudflare trace",
			body:        "fl=123\nip=203.0.113.8\nloc=jp\ntls=TLSv1.3\n",
			wantIP:      "203.0.113.8",
			wantCountry: "JP",
		},
		{
			name:        "json fields",
			body:        `{"ip":"2001:db8::8","country_code":"DE"}`,
			wantIP:      "2001:db8::8",
			wantCountry: "DE",
		},
		{
			name:        "alternate json fields",
			body:        `{"query":"198.51.100.9","countryCode":"US"}`,
			wantIP:      "198.51.100.9",
			wantCountry: "US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, country, err := parseExitProbeResponse([]byte(tt.body))
			if err != nil {
				t.Fatalf("parseExitProbeResponse returned error: %v", err)
			}
			if ip != tt.wantIP || country != tt.wantCountry {
				t.Fatalf("expected %s/%s, got %s/%s", tt.wantIP, tt.wantCountry, ip, country)
			}
		})
	}
}

func TestParseExitProbeResponseRejectsMissingFields(t *testing.T) {
	t.Parallel()

	if _, _, err := parseExitProbeResponse([]byte("ip=not-an-ip\nloc=USA\n")); err == nil {
		t.Fatal("expected invalid probe response to be rejected")
	}
}

func TestPersistedProxyRequiresThreeStartupFailuresBeforeRemoval(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy-selection.json")
	candidate := proxyCandidate{Addr: "stable.example:443"}
	if err := saveProxySelection(path, candidate); err != nil {
		t.Fatalf("saveProxySelection returned error: %v", err)
	}
	for want := 1; want <= 3; want++ {
		failures, cleared, err := recordProxySelectionFailure(path, candidate)
		if err != nil {
			t.Fatalf("recordProxySelectionFailure %d returned error: %v", want, err)
		}
		if failures != want {
			t.Fatalf("expected %d failures, got %d", want, failures)
		}
		if cleared != (want == 3) {
			t.Fatalf("unexpected cleared=%v after %d failures", cleared, want)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected persisted proxy state to be removed, got %v", err)
	}
}

type delayedTunnelOpener struct {
	started chan struct{}
	release chan struct{}
	conn    net.Conn
}

func (d *delayedTunnelOpener) OpenTunnel(string) (net.Conn, error) {
	close(d.started)
	<-d.release
	return d.conn, nil
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestOpenTunnelContextClosesConnectionThatArrivesAfterCancellation(t *testing.T) {
	t.Parallel()

	client, peer := net.Pipe()
	defer peer.Close()
	tracked := &closeTrackingConn{Conn: client}
	opener := &delayedTunnelOpener{
		started: make(chan struct{}),
		release: make(chan struct{}),
		conn:    tracked,
	}
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := openTunnelContext(ctx, opener, "example.com:443")
		resultCh <- result{conn: conn, err: err}
	}()

	<-opener.started
	cancel()
	got := <-resultCh
	if got.conn != nil || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("expected canceled dial, got conn=%v err=%v", got.conn, got.err)
	}
	close(opener.release)
	waitForCondition(t, time.Second, tracked.closed.Load)
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
	openCount   atomic.Int32
	closeCount  atomic.Int32
	updateCount atomic.Int32
	openErr     error
	updateErr   error
	tokenMu     sync.Mutex
	token       string
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

func (s *fakeProxySession) UpdateToken(token string) error {
	s.updateCount.Add(1)
	if s.updateErr != nil {
		return s.updateErr
	}
	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()
	return nil
}

func (s *fakeProxySession) currentToken() string {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	return s.token
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

type controlledNetConn struct {
	readErr error
	closed  chan struct{}
	once    sync.Once
}

func newControlledNetConn(readErr error) *controlledNetConn {
	return &controlledNetConn{readErr: readErr, closed: make(chan struct{})}
}

func (c *controlledNetConn) Read([]byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *controlledNetConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *controlledNetConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *controlledNetConn) LocalAddr() net.Addr              { return tunnelAddr("controlled") }
func (c *controlledNetConn) RemoteAddr() net.Addr             { return tunnelAddr("controlled") }
func (c *controlledNetConn) SetDeadline(time.Time) error      { return nil }
func (c *controlledNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *controlledNetConn) SetWriteDeadline(time.Time) error { return nil }

func TestProxyBidirectionalClosesBothSidesOnCopyError(t *testing.T) {
	t.Parallel()

	client := newControlledNetConn(errors.New("client read failed"))
	upstream := newControlledNetConn(nil)
	done := make(chan struct{})
	go func() {
		proxyBidirectional(client, upstream, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxyBidirectional did not close the blocked peer after copy error")
	}
	select {
	case <-upstream.closed:
	default:
		t.Fatal("expected upstream connection to be closed")
	}
}

type fakeHalfCloseConn struct {
	fakeNetConn
	closeReadCount  atomic.Int32
	closeWriteCount atomic.Int32
}

func (c *fakeHalfCloseConn) CloseRead() error {
	c.closeReadCount.Add(1)
	return nil
}

func (c *fakeHalfCloseConn) CloseWrite() error {
	c.closeWriteCount.Add(1)
	return nil
}

type halfCloseTestConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func TestTunnelWrappersForwardHalfCloseAndReleaseOnClose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		conn func(*fakeHalfCloseConn, *atomic.Int32) halfCloseTestConn
	}{
		{
			name: "pooled",
			conn: func(underlying *fakeHalfCloseConn, releaseCount *atomic.Int32) halfCloseTestConn {
				return &pooledTunnelConn{
					Conn: underlying,
					release: func() {
						releaseCount.Add(1)
					},
				}
			},
		},
		{
			name: "managed",
			conn: func(underlying *fakeHalfCloseConn, releaseCount *atomic.Int32) halfCloseTestConn {
				return &managedTunnelConn{
					Conn: underlying,
					release: func() {
						releaseCount.Add(1)
					},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			underlying := &fakeHalfCloseConn{}
			var releaseCount atomic.Int32
			conn := tc.conn(underlying, &releaseCount)

			assertHalfCloseForwarding(t, conn, underlying, &releaseCount)
		})
	}
}

func assertHalfCloseForwarding(t *testing.T, conn halfCloseTestConn, underlying *fakeHalfCloseConn, releaseCount *atomic.Int32) {
	t.Helper()

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite returned error: %v", err)
	}
	if got := underlying.closeWriteCount.Load(); got != 1 {
		t.Fatalf("expected underlying CloseWrite once, got %d", got)
	}

	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead returned error: %v", err)
	}
	if got := underlying.closeReadCount.Load(); got != 1 {
		t.Fatalf("expected underlying CloseRead once, got %d", got)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if got := releaseCount.Load(); got != 1 {
		t.Fatalf("expected pooled session release once, got %d", got)
	}
}

func TestProxySessionPoolDistributesTunnels(t *testing.T) {
	t.Parallel()

	sessions := []*fakeProxySession{{}, {}, {}}
	var created atomic.Int32
	pool, err := newProxySessionPool(len(sessions), func() (proxySession, error) {
		idx := int(created.Add(1)) - 1
		return sessions[idx], nil
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer pool.Close()

	for i := 0; i < 6; i++ {
		conn, err := pool.OpenTunnel("example.com:443")
		if err != nil {
			t.Fatalf("OpenTunnel %d returned error: %v", i, err)
		}
		_ = conn.Close()
	}

	for i, session := range sessions {
		if got := session.openCount.Load(); got != 2 {
			t.Fatalf("expected session %d open count 2, got %d", i, got)
		}
	}
}

func TestProxySessionPoolPinsClientToOneSession(t *testing.T) {
	t.Parallel()

	sessions := []*fakeProxySession{{}, {}, {}}
	var created atomic.Int32
	p, err := newProxySessionPool(len(sessions), func() (proxySession, error) {
		idx := int(created.Add(1)) - 1
		if idx >= len(sessions) {
			return nil, errors.New("replacement unavailable")
		}
		return sessions[idx], nil
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer p.Close()

	for i := 0; i < 6; i++ {
		conn, err := p.OpenTunnelForClient("example.com:443", "127.0.0.1")
		if err != nil {
			t.Fatalf("OpenTunnelForClient %d returned error: %v", i, err)
		}
		_ = conn.Close()
	}

	used := 0
	for i, session := range sessions {
		if got := session.openCount.Load(); got > 0 {
			used++
			if got != 6 {
				t.Fatalf("expected pinned session %d to receive all tunnels, got %d", i, got)
			}
		}
	}
	if used != 1 {
		t.Fatalf("expected one session to receive pinned client tunnels, used %d", used)
	}
}

func TestProxySessionPoolKeepsClientOnFailoverSession(t *testing.T) {
	t.Parallel()

	sessions := []*fakeProxySession{{}, {}, {}}
	var created atomic.Int32
	p, err := newProxySessionPool(len(sessions), func() (proxySession, error) {
		idx := int(created.Add(1)) - 1
		if idx >= len(sessions) {
			return nil, errors.New("replacement unavailable")
		}
		return sessions[idx], nil
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer p.Close()

	const clientKey = "127.0.0.1"
	failedSlot := p.nextSlot(clientKey)
	failoverSlot := (failedSlot + 1) % len(sessions)
	sessions[failedSlot].openErr = errors.New("transport closed")

	conn, err := p.OpenTunnelForClient("example.com:443", clientKey)
	if err != nil {
		t.Fatalf("OpenTunnelForClient failover returned error: %v", err)
	}
	_ = conn.Close()

	conn, err = p.OpenTunnelForClient("example.org:443", clientKey)
	if err != nil {
		t.Fatalf("OpenTunnelForClient after failover returned error: %v", err)
	}
	_ = conn.Close()

	if got := sessions[failedSlot].openCount.Load(); got != 1 {
		t.Fatalf("expected failed slot to be tried once, got %d", got)
	}
	if got := sessions[failoverSlot].openCount.Load(); got != 2 {
		t.Fatalf("expected failover slot to remain sticky, got %d opens", got)
	}
}

func TestProxySessionPoolUpdatesExistingAndReplacementTokens(t *testing.T) {
	t.Parallel()

	var factoryMu sync.Mutex
	createToken := "old-token"
	var sessions []*fakeProxySession
	p, err := newProxySessionPool(2, func() (proxySession, error) {
		factoryMu.Lock()
		defer factoryMu.Unlock()
		session := &fakeProxySession{token: createToken}
		sessions = append(sessions, session)
		return session, nil
	}, func(token string) {
		factoryMu.Lock()
		createToken = token
		factoryMu.Unlock()
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer p.Close()

	if err := p.UpdateToken("new-token"); err != nil {
		t.Fatalf("UpdateToken returned error: %v", err)
	}
	factoryMu.Lock()
	initial := append([]*fakeProxySession(nil), sessions...)
	factoryMu.Unlock()
	for i, session := range initial {
		if got := session.currentToken(); got != "new-token" {
			t.Fatalf("expected existing session %d token to update, got %q", i, got)
		}
	}

	failed := p.slot(0)
	p.retireSlot(0, failed)
	waitForCondition(t, time.Second, func() bool {
		factoryMu.Lock()
		defer factoryMu.Unlock()
		return len(sessions) >= 3
	})
	factoryMu.Lock()
	replacement := sessions[len(sessions)-1]
	factoryMu.Unlock()
	if got := replacement.currentToken(); got != "new-token" {
		t.Fatalf("expected replacement session to use renewed token, got %q", got)
	}
}

func TestProxySessionPoolUpdatesReplacementCreatedDuringRenewal(t *testing.T) {
	t.Parallel()

	var factoryMu sync.Mutex
	createToken := "old-token"
	createCalls := 0
	replacementStarted := make(chan struct{})
	releaseReplacement := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseReplacement) })
	var sessions []*fakeProxySession
	p, err := newProxySessionPool(2, func() (proxySession, error) {
		factoryMu.Lock()
		createCalls++
		call := createCalls
		token := createToken
		factoryMu.Unlock()
		if call == 3 {
			close(replacementStarted)
			<-releaseReplacement
		}
		session := &fakeProxySession{token: token}
		factoryMu.Lock()
		sessions = append(sessions, session)
		factoryMu.Unlock()
		return session, nil
	}, func(token string) {
		factoryMu.Lock()
		createToken = token
		factoryMu.Unlock()
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer p.Close()

	p.retireSlot(0, p.slot(0))
	select {
	case <-replacementStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement session creation did not start")
	}
	if err := p.UpdateToken("new-token"); err != nil {
		t.Fatalf("UpdateToken returned error: %v", err)
	}
	releaseOnce.Do(func() { close(releaseReplacement) })
	waitForCondition(t, time.Second, func() bool { return p.slot(0) != nil })

	factoryMu.Lock()
	replacement := sessions[len(sessions)-1]
	factoryMu.Unlock()
	if got := replacement.currentToken(); got != "new-token" {
		t.Fatalf("expected in-flight replacement to receive renewed token, got %q", got)
	}
}

func TestProxySessionPoolSkipsBrokenSession(t *testing.T) {
	t.Parallel()

	broken := &fakeProxySession{openErr: errors.New("transport closed")}
	healthy := &fakeProxySession{}
	replacement := &fakeProxySession{}
	sessions := []*fakeProxySession{broken, healthy, replacement}
	var created atomic.Int32
	pool, err := newProxySessionPool(2, func() (proxySession, error) {
		idx := int(created.Add(1)) - 1
		return sessions[idx], nil
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer pool.Close()

	conn, err := pool.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel returned error: %v", err)
	}
	_ = conn.Close()

	if got := healthy.openCount.Load(); got != 1 {
		t.Fatalf("expected healthy session open count 1, got %d", got)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("pool Close returned error: %v", err)
	}
	if got := broken.closeCount.Load(); got != 1 {
		t.Fatalf("expected broken session to be closed once, got %d", got)
	}
}

func TestProxySessionPoolStartsWithPartialSuccess(t *testing.T) {
	t.Parallel()

	session := &fakeProxySession{}
	var attempts atomic.Int32
	pool, err := newProxySessionPool(3, func() (proxySession, error) {
		n := attempts.Add(1)
		if n == 1 {
			return session, nil
		}
		return nil, errors.New("temporary dial failure")
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer pool.Close()

	conn, err := pool.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel returned error: %v", err)
	}
	_ = conn.Close()
	if got := session.openCount.Load(); got != 1 {
		t.Fatalf("expected available session open count 1, got %d", got)
	}
}

func TestProxySessionPoolReplenishesBrokenSession(t *testing.T) {
	t.Parallel()

	broken := &fakeProxySession{openErr: errors.New("transport closed")}
	healthy := &fakeProxySession{}
	replacement := &fakeProxySession{}
	sessions := []*fakeProxySession{broken, healthy, replacement}
	var created atomic.Int32
	pool, err := newProxySessionPool(2, func() (proxySession, error) {
		idx := int(created.Add(1)) - 1
		if idx >= len(sessions) {
			return nil, errors.New("unexpected extra create")
		}
		return sessions[idx], nil
	})
	if err != nil {
		t.Fatalf("newProxySessionPool returned error: %v", err)
	}
	defer pool.Close()

	conn, err := pool.OpenTunnel("example.com:443")
	if err != nil {
		t.Fatalf("OpenTunnel returned error: %v", err)
	}
	_ = conn.Close()

	waitForCondition(t, time.Second, func() bool {
		return pool.slot(0) != nil
	})

	for i := 0; i < 2; i++ {
		conn, err := pool.OpenTunnel("example.org:443")
		if err != nil {
			t.Fatalf("OpenTunnel after replenish returned error: %v", err)
		}
		_ = conn.Close()
	}
	if got := replacement.openCount.Load(); got == 0 {
		t.Fatal("expected replenished session to receive a tunnel")
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

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

func TestProxySessionsUpdateBearerToken(t *testing.T) {
	t.Parallel()

	h2Session := &h2ProxySession{token: "old-token"}
	if err := h2Session.UpdateToken("new-token"); err != nil {
		t.Fatalf("h2 UpdateToken returned error: %v", err)
	}
	if got := h2Session.bearerToken(); got != "new-token" {
		t.Fatalf("expected h2 token update, got %q", got)
	}

	h3Session := &h3ProxySession{token: "old-token"}
	if err := h3Session.UpdateToken("new-token"); err != nil {
		t.Fatalf("h3 UpdateToken returned error: %v", err)
	}
	if got := h3Session.bearerToken(); got != "new-token" {
		t.Fatalf("expected h3 token update, got %q", got)
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

func TestSessionFailureTrackerRequiresDistinctTargets(t *testing.T) {
	t.Parallel()

	tracker := &sessionFailureTracker{}
	timeoutErr := &tunnelOpenTimeoutError{timeout: time.Second}
	for i := 0; i < 5; i++ {
		if err := tracker.observe("same.example:443", timeoutErr); errors.Is(err, errProxySessionUnhealthy) {
			t.Fatal("repeated failure for one target should not retire the session")
		}
	}
	if err := tracker.observe("second.example:443", timeoutErr); errors.Is(err, errProxySessionUnhealthy) {
		t.Fatal("two failed targets should not retire the session")
	}
	if err := tracker.observe("third.example:443", timeoutErr); !errors.Is(err, errProxySessionUnhealthy) {
		t.Fatalf("expected three distinct timeout targets to retire the session, got %v", err)
	}

	tracker.observe("healthy.example:443", nil)
	badGateway := &proxyConnectHTTPError{statusCode: http.StatusBadGateway, status: "502 Bad Gateway"}
	if err := tracker.observe("one.example:443", badGateway); errors.Is(err, errProxySessionUnhealthy) {
		t.Fatal("one 502 target should not retire the session")
	}
	if err := tracker.observe("two.example:443", badGateway); errors.Is(err, errProxySessionUnhealthy) {
		t.Fatal("two 502 targets should not retire the session")
	}
	if err := tracker.observe("three.example:443", badGateway); !errors.Is(err, errProxySessionUnhealthy) {
		t.Fatalf("expected three distinct 502 targets to retire the session, got %v", err)
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

func TestProxyControllerUpdatesTokenWithoutReplacingSession(t *testing.T) {
	t.Parallel()

	session := &fakeProxySession{token: "old-token"}
	oldExpiry := time.Now().Add(10 * time.Minute)
	newExpiry := time.Now().Add(20 * time.Minute)
	controller := &proxyController{
		current: &managedSession{
			session:   session,
			expiresAt: oldExpiry,
			accepting: true,
		},
	}

	if err := controller.updateCurrentSessionToken("new-token", newExpiry); err != nil {
		t.Fatalf("updateCurrentSessionToken returned error: %v", err)
	}
	if controller.current.session != session {
		t.Fatal("expected token renewal to retain the existing upstream session")
	}
	if got := session.currentToken(); got != "new-token" {
		t.Fatalf("expected renewed token, got %q", got)
	}
	if !controller.current.expiresAt.Equal(newExpiry) {
		t.Fatalf("expected expiry %s, got %s", newExpiry, controller.current.expiresAt)
	}
	if session.closeCount.Load() != 0 {
		t.Fatalf("expected retained session to stay open, got %d closes", session.closeCount.Load())
	}
}

func TestProxyControllerRejectsSessionSwapAfterClose(t *testing.T) {
	t.Parallel()

	controller := &proxyController{closed: true}
	newSession := &fakeProxySession{}
	if controller.swapSession(newSession, time.Now().Add(time.Minute)) {
		t.Fatal("expected closed controller to reject session swap")
	}
	if got := newSession.closeCount.Load(); got != 1 {
		t.Fatalf("expected rejected session to be closed once, got %d", got)
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

func TestProxyControllerSleepOrDoneWakesOnClose(t *testing.T) {
	t.Parallel()

	controller := &proxyController{done: make(chan struct{})}
	done := make(chan bool, 1)
	go func() {
		done <- controller.sleepOrDone(time.Hour)
	}()

	if err := controller.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case keptGoing := <-done:
		if keptGoing {
			t.Fatal("expected sleepOrDone to stop after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("sleepOrDone did not wake after Close")
	}
}

func TestProxyControllerWritesStatusFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	statusFile := filepath.Join(dir, "status.json")
	controller := &proxyController{
		statusFile: statusFile,
		current: &managedSession{
			session:   &fakeProxySession{},
			expiresAt: time.Now().Add(10 * time.Minute),
			accepting: true,
		},
	}

	controller.writeStatus("startup")
	controller.writeStatus("renewed")

	data, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	var status proxyRuntimeStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if status.Reason != "renewed" {
		t.Fatalf("expected reason renewed, got %q", status.Reason)
	}
	if status.ProxyPassExpiresAt == "" {
		t.Fatal("expected proxy_pass_expires_at to be populated")
	}
	if !status.Accepting {
		t.Fatal("expected accepting=true")
	}
}

func TestProxyControllerRenewWithTimeoutTimesOut(t *testing.T) {
	t.Parallel()

	controller := &proxyController{done: make(chan struct{})}
	controller.renewMu.Lock()
	defer controller.renewMu.Unlock()

	timedOutCh := make(chan bool, 1)
	go func() {
		_, timedOut := controller.renewWithTimeout(20 * time.Millisecond)
		timedOutCh <- timedOut
	}()

	select {
	case timedOut := <-timedOutCh:
		if !timedOut {
			t.Fatal("expected renewWithTimeout to time out")
		}
	case <-time.After(time.Second):
		t.Fatal("renewWithTimeout did not return")
	}
}

func TestProxyControllerRenewWithTimeoutStopsWhenClosed(t *testing.T) {
	t.Parallel()

	controller := &proxyController{done: make(chan struct{})}
	close(controller.done)

	_, timedOut := controller.renewWithTimeout(time.Hour)
	if timedOut {
		t.Fatal("expected closed controller not to report renewal timeout")
	}
}
