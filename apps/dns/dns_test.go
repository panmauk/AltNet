package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// TestCapturedNameReturnsConfiguredIP verifies the primary purpose of the
// resolver: an A query for a captured TLD returns an A record pointing at
// captureIP. Without this, "type panmox.alt, see content" doesn't work.
func TestCapturedNameReturnsConfiguredIP(t *testing.T) {
	captureIP := net.ParseIP("127.0.0.1")
	r := New([]string{"alt"}, captureIP, "127.0.0.1:65535") // upstream is junk, doesn't matter
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	addr := r.LocalAddr().String()

	// Build a textbook A query for "panmox.alt".
	query := buildAQuery(0x1234, "panmox.alt")
	reply := mustQuery(t, addr, query)

	// Sanity-check the response header.
	if id := binary.BigEndian.Uint16(reply[0:2]); id != 0x1234 {
		t.Errorf("response ID = 0x%x, want 0x1234", id)
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&0x8000 == 0 {
		t.Error("response QR bit not set")
	}
	if rcode := flags & 0x0F; rcode != 0 {
		t.Errorf("response RCODE = %d, want 0 (NOERROR)", rcode)
	}
	ancount := binary.BigEndian.Uint16(reply[6:8])
	if ancount != 1 {
		t.Fatalf("response ANCOUNT = %d, want 1", ancount)
	}

	// Find the A record (4 bytes at the end of the reply).
	if len(reply) < 4 {
		t.Fatal("response too short to contain A record")
	}
	ip := net.IP(reply[len(reply)-4:])
	if !ip.Equal(captureIP) {
		t.Errorf("returned IP = %s, want %s", ip, captureIP)
	}
}

// TestUncapturedNameForwarded verifies that a query for a domain we DON'T
// capture is forwarded to the upstream resolver. We set up our own tiny
// upstream that returns a deterministic answer and confirm we see it.
func TestUncapturedNameForwarded(t *testing.T) {
	// Spin up a fake upstream that returns 9.9.9.9 for any A query.
	upstream, fakeUpstreamAddr := startFakeUpstream(t, net.ParseIP("9.9.9.9"))
	defer upstream.Close()

	r := New([]string{"alt"}, net.ParseIP("127.0.0.1"), fakeUpstreamAddr)
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	addr := r.LocalAddr().String()

	// Query a non-altnet domain -- should be forwarded.
	query := buildAQuery(0xBEEF, "example.com")
	reply := mustQuery(t, addr, query)

	if len(reply) < 4 {
		t.Fatal("response too short")
	}
	ip := net.IP(reply[len(reply)-4:])
	if !ip.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("forwarded result = %s, want 9.9.9.9", ip)
	}
}

// TestAAAAOnCapturedNameIsEmpty verifies that an AAAA (IPv6) query for a
// captured name returns NOERROR with 0 answers, so browsers fall back to
// the A record instead of failing the resolution outright.
func TestAAAAOnCapturedNameIsEmpty(t *testing.T) {
	r := New([]string{"alt"}, net.ParseIP("127.0.0.1"), "127.0.0.1:65535")
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	query := buildQueryWithType(0xCAFE, "panmox.alt", 28) // AAAA
	reply := mustQuery(t, r.LocalAddr().String(), query)

	flags := binary.BigEndian.Uint16(reply[2:4])
	if rcode := flags & 0x0F; rcode != 0 {
		t.Errorf("AAAA RCODE = %d, want 0 (NOERROR)", rcode)
	}
	ancount := binary.BigEndian.Uint16(reply[6:8])
	if ancount != 0 {
		t.Errorf("AAAA ANCOUNT = %d, want 0", ancount)
	}
}

// TestMatchesCapture is a quick unit test of the TLD-matching predicate.
func TestMatchesCapture(t *testing.T) {
	r := New([]string{"alt"}, net.ParseIP("127.0.0.1"), "")
	cases := []struct {
		name string
		want bool
	}{
		{"panmox.alt", true},
		{"sub.domain.alt", true},
		{"alt", true},
		{"google.com", false},
		{"altnet.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := r.matchesCapture(tc.name); got != tc.want {
			t.Errorf("matchesCapture(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// --- helpers ---

// buildAQuery constructs a minimal type-A class-IN DNS query.
func buildAQuery(id uint16, name string) []byte {
	return buildQueryWithType(id, name, 1)
}

func buildQueryWithType(id uint16, name string, qtype uint16) []byte {
	out := make([]byte, 0, 64)
	// Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT=1
	out = append(out, header...)
	// QNAME
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0) // root label
	// QTYPE / QCLASS
	tc := make([]byte, 4)
	binary.BigEndian.PutUint16(tc[0:2], qtype)
	binary.BigEndian.PutUint16(tc[2:4], 1) // IN
	out = append(out, tc...)
	return out
}

// mustQuery sends query to addr over UDP and returns the response, or
// fails the test on any error/timeout.
func mustQuery(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// startFakeUpstream is a 1-record DNS server that replies to any A query
// with the given IP. It mimics just enough of the protocol for our forward
// test to work.
func startFakeUpstream(t *testing.T, replyIP net.IP) (*net.UDPConn, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			// Find the question end the same way the resolver does.
			_, nameLen, _ := readName(req, 12)
			qEnd := 12 + nameLen + 4
			if qEnd > len(req) {
				continue
			}
			// Build reply: ID + (QR|AA|RD|RA), QDCOUNT=1, ANCOUNT=1, copy
			// the question, append A record pointing at replyIP.
			out := make([]byte, qEnd)
			copy(out, req[:qEnd])
			binary.BigEndian.PutUint16(out[2:4], 0x8580)
			binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT
			out = append(out, 0xC0, 0x0C)
			out = append(out, 0x00, 0x01)             // type A
			out = append(out, 0x00, 0x01)             // class IN
			out = append(out, 0x00, 0x00, 0x00, 0x3C) // TTL
			out = append(out, 0x00, 0x04)             // RDLENGTH
			ip4 := replyIP.To4()
			out = append(out, ip4[0], ip4[1], ip4[2], ip4[3])
			_, _ = conn.WriteToUDP(out, src)
		}
	}()
	return conn, conn.LocalAddr().String()
}
