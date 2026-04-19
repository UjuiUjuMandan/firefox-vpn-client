package main

import (
	"bytes"
	"errors"
	"io"
	"net"
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
			Cities: []vpnclient.City{
				{
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

type fakeProxySession struct {
	openCount  atomic.Int32
	closeCount atomic.Int32
}

func (s *fakeProxySession) OpenTunnel(authority string) (net.Conn, error) {
	s.openCount.Add(1)
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
