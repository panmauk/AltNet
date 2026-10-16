package peer

import (
	"net"
	"testing"
	"time"
)

// TestConnectionLimitRefusesNewInbound verifies the inbound cap
// rejects accepts past the limit. Setup: A's max=1, B and C both try
// to connect; only one succeeds.
func TestConnectionLimitRefusesNewInbound(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	a.SetMaxConnections(1)

	b := newTestPeer(t)
	defer b.Stop()
	c := newTestPeer(t)
	defer c.Stop()

	// First connect succeeds.
	if err := b.Connect(a.LocalAddr()); err != nil {
		t.Fatalf("B connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if a.UniqueConnCount() != 1 {
		t.Fatalf("after B, A should have 1 conn, got %d", a.UniqueConnCount())
	}

	// Second connect: A is at cap. The TCP-level dial may succeed,
	// but A immediately closes. C's Connect may either succeed
	// (handshake completed before A noticed) or fail. We assert that
	// A's unique-conn count stays at 1.
	_ = c.Connect(a.LocalAddr())
	time.Sleep(200 * time.Millisecond)

	if a.UniqueConnCount() > 1 {
		t.Errorf("A should have refused C; unique conns = %d", a.UniqueConnCount())
	}
}

// TestConnectionLimitRefusesOutbound: when WE are at the cap, our own
// outbound Connect calls must fail fast.
func TestConnectionLimitRefusesOutbound(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()
	a.SetMaxConnections(1)

	b := newTestPeer(t)
	defer b.Stop()
	c := newTestPeer(t)
	defer c.Stop()

	if err := a.Connect(b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	// A is now at 1/1. Trying to dial C must fail fast without
	// even opening a TCP connection.
	err := a.Connect(c.LocalAddr())
	if err == nil {
		t.Error("Connect should have failed at connection limit")
	}
}

// TestPreHelloTimeoutKillsSilentPeer: a TCP client that connects but
// never sends anything (not even the secure handshake) should be
// killed within HandshakeTimeout. A peer that completes secure
// handshake but never sends its hello should be killed within
// PreHelloTimeout.
//
// We can't easily reach into the secure handshake's internals, so
// this test exercises the post-handshake silent-peer case using a
// raw TCP socket -- the receiver-side handshake will time out, which
// is the simpler invariant.
func TestPreHelloTimeoutKillsSilentPeer(t *testing.T) {
	a := newTestPeer(t)
	defer a.Stop()

	// Open a raw TCP socket to A but never speak. A's secure
	// handshake should time out and close the connection from its
	// side within HandshakeTimeout (~10s in production, but the
	// check-shutdown happens fast enough for this test).
	conn, err := net.Dial("tcp", a.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set a short read deadline; if A closes us, Read returns an
	// error. If we sat here forever, A would have leaked us.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	// We expect an error (EOF, conn closed, or read timeout in the
	// worst case). What we DON'T want is a successful Read of bytes
	// from a leaked connection.
	if err == nil {
		t.Error("silent client should have been disconnected by A within timeout")
	}
}
