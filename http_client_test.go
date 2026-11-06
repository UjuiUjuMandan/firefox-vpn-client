package vpnclient

import (
	"encoding/binary"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestControlPlaneTransportDialsFirefoxHello guards the uTLS dialer: since
// early November 2026 the Fastly edge rejects VPN scope token requests whose
// ClientHello matches Go's bot-listed crypto/tls signature, so the control
// plane must present a Firefox ClientHello instead.
func TestControlPlaneTransportDialsFirefoxHello(t *testing.T) {
	t.Parallel()

	transport := NewControlPlaneTransport()
	if transport.DialTLS == nil {
		t.Fatal("DialTLS must be set (uTLS Firefox ClientHello)")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	helloCh := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(helloCh)
			return
		}
		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ := conn.Read(buf)
		conn.Close()
		helloCh <- buf[:n]
	}()

	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/", nil)
	// The request fails: the listener closes the connection mid-handshake.
	// Only the captured ClientHello matters.
	client.Do(req)

	hello, ok := <-helloCh
	if !ok || len(hello) < 48 {
		t.Fatalf("no ClientHello captured (%d bytes)", len(hello))
	}
	if hello[0] != 0x16 {
		t.Fatalf("not a TLS handshake record: first byte %#x", hello[0])
	}

	// record(5) + handshake header(4) + version(2) + random(32) = 43
	pos := 43
	sidLen := int(hello[pos])
	pos += 1 + sidLen
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	cipherCount := csLen / 2
	firstCipher := binary.BigEndian.Uint16(hello[pos+2 : pos+4])
	has0035, has009c := false, false
	for i := 0; i < cipherCount; i++ {
		switch binary.BigEndian.Uint16(hello[pos+2+2*i : pos+4+2*i]) {
		case 0x0035:
			has0035 = true
		case 0x009c:
			has009c = true
		}
	}
	// Firefox puts TLS 1.3 suites first and still offers legacy RSA/AEAD
	// suites (0x0035, 0x009c); Go's default hello has 13 suites, leads with
	// ECDHE, puts TLS 1.3 last, and omits 0x0035/0x009c entirely.
	if firstCipher != 0x1301 || !has0035 || !has009c || cipherCount < 15 {
		t.Fatalf("ClientHello is not the uTLS Firefox preset: first=%#04x count=%d legacy0035=%v legacy009c=%v", firstCipher, cipherCount, has0035, has009c)
	}
}
