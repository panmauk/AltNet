package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakePeerID returns a 64-char hex string usable as a peer ID for tests.
func fakePeerID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:])
}

// startRelay spins up a Server bound to an ephemeral port and returns its
// address.
func startRelay(t *testing.T) (*Server, string) {
	t.Helper()
	s := NewServer()
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	return s, s.LocalAddr().String()
}

// TestRegisterAndDialTunnelsBytes is the headline test. A registers with
// R; B dials A through R; both ends of the tunnel exchange bytes both
// directions and the bytes match.
func TestRegisterAndDialTunnelsBytes(t *testing.T) {
	srv, addr := startRelay(t)
	defer srv.Stop()

	// A registers.
	aID := fakePeerID("alice")
	a := NewClient(addr, aID)
	go a.Run()
	defer a.Stop()

	// Wait for the registration to land on the server.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.RegistrationCount() != 1 {
		t.Fatal("alice never registered")
	}

	// B dials A through the relay.
	bConn, err := DialVia(addr, aID)
	if err != nil {
		t.Fatalf("DialVia: %v", err)
	}
	defer bConn.Close()

	// A sees the incoming tunnel.
	var aConn net.Conn
	select {
	case aConn = <-a.Tunnels:
	case <-time.After(2 * time.Second):
		t.Fatal("alice never got tunnel")
	}
	defer aConn.Close()

	// B -> A
	go func() {
		bConn.Write([]byte("hello alice"))
	}()
	buf := make([]byte, 64)
	n, err := aConn.Read(buf)
	if err != nil {
		t.Fatalf("alice read: %v", err)
	}
	if got := string(buf[:n]); got != "hello alice" {
		t.Errorf("alice got %q, want %q", got, "hello alice")
	}

	// A -> B
	go func() {
		aConn.Write([]byte("hi bob"))
	}()
	n, err = bConn.Read(buf)
	if err != nil {
		t.Fatalf("bob read: %v", err)
	}
	if got := string(buf[:n]); got != "hi bob" {
		t.Errorf("bob got %q, want %q", got, "hi bob")
	}
}

// TestDialUnregisteredPeerErrors confirms we get a clean error when
// trying to reach a peer that hasn't registered.
func TestDialUnregisteredPeerErrors(t *testing.T) {
	srv, addr := startRelay(t)
	defer srv.Stop()

	_, err := DialVia(addr, fakePeerID("nobody"))
	if err == nil {
		t.Fatal("expected error dialing unregistered peer")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error should mention not registered, got: %v", err)
	}
}

// TestRegisterReplacesPriorRegistration: if two clients register the
// same peer ID, only the most recent one wins (and the old conn is
// closed). Real-world: a peer reconnected after a network blip.
func TestRegisterReplacesPriorRegistration(t *testing.T) {
	srv, addr := startRelay(t)
	defer srv.Stop()

	id := fakePeerID("alice")
	a1 := NewClient(addr, id)
	go a1.Run()
	defer a1.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Second client registers the same ID.
	a2 := NewClient(addr, id)
	go a2.Run()
	defer a2.Stop()

	// Give the server time to process.
	time.Sleep(300 * time.Millisecond)

	if got := srv.RegistrationCount(); got != 1 {
		t.Errorf("RegistrationCount = %d, want 1 (a2 should have replaced a1)", got)
	}

	// A new DIAL should reach a2, not a1.
	bConn, err := DialVia(addr, id)
	if err != nil {
		t.Fatalf("DialVia: %v", err)
	}
	defer bConn.Close()

	select {
	case <-a2.Tunnels:
		// good -- a2 got the tunnel
	case tun := <-a1.Tunnels:
		tun.Close()
		t.Error("a1 got the tunnel, but a2 should have replaced it")
	case <-time.After(2 * time.Second):
		t.Fatal("neither client got the tunnel")
	}
}

// TestStopClosesEverything verifies that Stop on the server tears down
// active registrations cleanly.
func TestStopClosesEverything(t *testing.T) {
	srv, addr := startRelay(t)

	a := NewClient(addr, fakePeerID("a"))
	go a.Run()
	defer a.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	srv.Stop()

	// After Stop, the server's address should not accept new connections.
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("server should not accept after Stop")
	}
}

// TestLargePayloadThroughTunnel pushes ~256 KiB through the relay and
// verifies it arrives intact. Exercises the pipe loop's buffer handling.
func TestLargePayloadThroughTunnel(t *testing.T) {
	srv, addr := startRelay(t)
	defer srv.Stop()

	id := fakePeerID("alice")
	a := NewClient(addr, id)
	go a.Run()
	defer a.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RegistrationCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	bConn, err := DialVia(addr, id)
	if err != nil {
		t.Fatalf("DialVia: %v", err)
	}
	defer bConn.Close()

	var aConn net.Conn
	select {
	case aConn = <-a.Tunnels:
	case <-time.After(2 * time.Second):
		t.Fatal("no tunnel")
	}
	defer aConn.Close()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 16*1024) // 256 KiB
	go func() {
		bConn.Write(payload)
	}()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	deadline = time.Now().Add(5 * time.Second)
	for len(got) < len(payload) && time.Now().Before(deadline) {
		_ = aConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := aConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestBadCommandRejected ensures a totally malformed first line gets
// dropped without panicking the server.
func TestBadCommandRejected(t *testing.T) {
	srv, addr := startRelay(t)
	defer srv.Stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("WAT\n"))

	// Server should reply ERR and close.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n == 0 || !strings.HasPrefix(string(buf[:n]), RespErr) {
		t.Errorf("expected ERR response, got %q", string(buf[:n]))
	}
}
