// Package dns implements a tiny UDP DNS resolver.
//
// Its job is split:
//
//  1. CAPTURE: when a client asks for an A record under one of our
//     captured TLDs (e.g. "panmox.alt"), reply with the configured
//     gateway IP (typically 127.0.0.1). The client's HTTP request will
//     then arrive at our gateway with the original hostname in the Host
//     header, and the gateway will resolve it via the DHT name layer.
//
//  2. FORWARD: any other query is forwarded to an upstream resolver
//     (default 1.1.1.1:53) and the reply is relayed back. This lets the
//     daemon serve as the user's primary DNS resolver without breaking
//     the regular internet.
//
// We implement only the small slice of DNS we need:
//   - Standard query (OPCODE=0)
//   - Class IN (1)
//   - Type A (1) and AAAA (28); for AAAA on captured names we return an
//     empty answer (NOERROR with 0 answers) so the browser falls back
//     to the A record.
//   - Names made of length-prefixed labels, no compression in the
//     question (compression in the answer is fine because we use the
//     0xC00C pointer to point back at the question).
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultUpstream is the resolver we forward non-captured queries to.
const DefaultUpstream = "1.1.1.1:53"

// DefaultPerSourceQPS is the per-IP rate cap for DNS queries. UDP
// source addresses are spoofable, so an unrestricted DNS resolver is
// a reflection-amplification weapon (small query in, bigger response
// out, attacker spoofs the victim's IP, victim gets flooded). The
// rate limiter caps how much we'll amplify toward any single source.
const DefaultPerSourceQPS = 50

// DefaultPerSourceBurst is the burst capacity above the steady QPS.
const DefaultPerSourceBurst = 100

// Resolver is a UDP DNS server that captures one or more TLDs and
// forwards everything else.
type Resolver struct {
	captureTLDs []string // lowercased, no leading dot, e.g. ["alt"]
	captureIP   net.IP   // typically 127.0.0.1; the gateway's IP
	upstream    string   // host:port

	limiter *udpRateLimiter

	conn    *net.UDPConn
	stopped atomic.Bool
}

// New creates a Resolver. captureTLDs is a list of bare TLD strings
// ("alt", not ".alt"). captureIP is the IP address to return for
// A queries under any captured TLD.
func New(captureTLDs []string, captureIP net.IP, upstream string) *Resolver {
	return NewWithRate(captureTLDs, captureIP, upstream, DefaultPerSourceQPS, DefaultPerSourceBurst)
}

// NewWithRate is New plus explicit per-source rate / burst limits.
// qps=0 disables the limiter (don't do this on a public resolver).
func NewWithRate(captureTLDs []string, captureIP net.IP, upstream string, qps, burst int) *Resolver {
	if upstream == "" {
		upstream = DefaultUpstream
	}
	tlds := make([]string, len(captureTLDs))
	for i, t := range captureTLDs {
		tlds[i] = strings.ToLower(strings.TrimPrefix(t, "."))
	}
	r := &Resolver{
		captureTLDs: tlds,
		captureIP:   captureIP.To4(),
		upstream:    upstream,
	}
	if qps > 0 {
		r.limiter = newUDPRateLimiter(qps, burst)
	}
	return r
}

// Start begins listening on addr (host:port). Returns immediately after
// binding; replies are served from a background goroutine. Call Stop to
// shut down cleanly.
func (r *Resolver) Start(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	r.conn = conn
	go r.serve()
	return nil
}

// LocalAddr returns the address actually bound. Useful when starting on
// an ephemeral port (":0") in tests.
func (r *Resolver) LocalAddr() net.Addr {
	if r.conn == nil {
		return nil
	}
	return r.conn.LocalAddr()
}

// Stop closes the listener. Pending queries return EOF.
func (r *Resolver) Stop() {
	r.stopped.Store(true)
	if r.conn != nil {
		r.conn.Close()
	}
}

func (r *Resolver) serve() {
	buf := make([]byte, 1500) // standard ethernet MTU; DNS over UDP is 512 bytes by default
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if r.stopped.Load() {
				return
			}
			// Transient error -- keep going.
			continue
		}
		// Copy because the buffer is reused.
		req := make([]byte, n)
		copy(req, buf[:n])
		go r.handle(req, src)
	}
}

func (r *Resolver) handle(req []byte, src *net.UDPAddr) {
	// Rate-limit per source IP to bound the amplification factor.
	// UDP source IPs are spoofable, so an attacker can always cause
	// SOME amplification toward a victim, but the per-IP cap keeps
	// the multiplication factor below abusive levels.
	if r.limiter != nil && !r.limiter.allow(src.IP.String()) {
		return // drop silently
	}
	q, err := parseQuery(req)
	if err != nil {
		return // malformed; drop silently like real resolvers
	}

	// Check whether the query name ends with one of our captured TLDs.
	if r.matchesCapture(q.name) {
		reply, err := r.buildCapturedReply(req, q)
		if err == nil {
			_, _ = r.conn.WriteToUDP(reply, src)
			return
		}
		// fall through to forwarding if we couldn't build a reply
	}

	// Forward to upstream.
	reply, err := forward(r.upstream, req, 3*time.Second)
	if err != nil {
		return // forwarding failed; drop. Client will time out and retry.
	}
	_, _ = r.conn.WriteToUDP(reply, src)
}

// matchesCapture reports whether name has a TLD we should capture.
// "panmox.alt" with captureTLDs=["alt"] -> true.
// "google.com" -> false.
func (r *Resolver) matchesCapture(name string) bool {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, tld := range r.captureTLDs {
		if lower == tld || strings.HasSuffix(lower, "."+tld) {
			return true
		}
	}
	return false
}

// --- DNS wire-format parsing & response building ---

type question struct {
	name  string // dot-separated, no trailing dot
	qtype uint16
	class uint16
}

type parsedQuery struct {
	id      uint16
	flags   uint16
	qdcount uint16
	question
	rawQuestionStart int // byte offset of the question section
}

// parseQuery extracts the first question from a DNS query. We only support
// queries with exactly one question; multi-question queries are rare in
// practice.
func parseQuery(p []byte) (*parsedQuery, error) {
	if len(p) < 12 {
		return nil, errors.New("dns: short header")
	}
	q := &parsedQuery{
		id:      binary.BigEndian.Uint16(p[0:2]),
		flags:   binary.BigEndian.Uint16(p[2:4]),
		qdcount: binary.BigEndian.Uint16(p[4:6]),
	}
	if q.qdcount < 1 {
		return nil, errors.New("dns: no question")
	}
	off := 12
	q.rawQuestionStart = off

	name, n, err := readName(p, off)
	if err != nil {
		return nil, err
	}
	off += n

	if off+4 > len(p) {
		return nil, errors.New("dns: truncated question")
	}
	q.qtype = binary.BigEndian.Uint16(p[off : off+2])
	q.class = binary.BigEndian.Uint16(p[off+2 : off+4])
	q.name = name
	return q, nil
}

// readName decodes a label-encoded DNS name starting at offset off.
// Returns the dot-separated name and the number of bytes consumed.
// It does NOT follow compression pointers (questions never use them).
func readName(p []byte, off int) (string, int, error) {
	var labels []string
	start := off
	for {
		if off >= len(p) {
			return "", 0, errors.New("dns: name truncated")
		}
		l := int(p[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			return "", 0, errors.New("dns: compression in question (unsupported)")
		}
		if l > 63 {
			return "", 0, errors.New("dns: label too long")
		}
		off++
		if off+l > len(p) {
			return "", 0, errors.New("dns: label truncated")
		}
		labels = append(labels, string(p[off:off+l]))
		off += l
		if off-start > 255 {
			return "", 0, errors.New("dns: name too long")
		}
	}
	return strings.Join(labels, "."), off - start, nil
}

// buildCapturedReply constructs an A-record (or empty AAAA) response that
// reuses the question section verbatim and points an answer at captureIP.
func (r *Resolver) buildCapturedReply(req []byte, q *parsedQuery) ([]byte, error) {
	// We need to know where the question ends so we can copy it verbatim
	// into the response. parseQuery consumed exactly 12 + nameBytes + 4
	// bytes, but it didn't return that. Recompute:
	_, nameLen, err := readName(req, 12)
	if err != nil {
		return nil, err
	}
	qEnd := 12 + nameLen + 4

	// Header: same ID, flags = response (QR=1) + RD copied from request +
	// RA=1, RCODE=NOERROR. AA=1 because we're authoritative for the
	// captured zone.
	const QR = 1 << 15
	const AA = 1 << 10
	const RD = 1 << 8
	const RA = 1 << 7
	flags := uint16(QR | AA | RA)
	if q.flags&RD != 0 {
		flags |= RD
	}

	out := make([]byte, qEnd)
	copy(out, req[:qEnd])
	binary.BigEndian.PutUint16(out[0:2], q.id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT

	switch q.qtype {
	case 1: // A
		binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)

		ans := make([]byte, 0, 16)
		// NAME pointer to question (offset 12).
		ans = append(ans, 0xC0, 0x0C)
		// TYPE A
		ans = append(ans, 0x00, 0x01)
		// CLASS IN
		ans = append(ans, 0x00, 0x01)
		// TTL 60 seconds
		ans = append(ans, 0x00, 0x00, 0x00, 0x3C)
		// RDLENGTH 4
		ans = append(ans, 0x00, 0x04)
		ans = append(ans, r.captureIP[0], r.captureIP[1], r.captureIP[2], r.captureIP[3])

		out = append(out, ans...)

	case 28: // AAAA
		// We don't have IPv6, but returning NOERROR with 0 answers makes
		// most browsers fall back to the A record cleanly.
		binary.BigEndian.PutUint16(out[6:8], 0) // ANCOUNT
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)

	default:
		// Other types (MX, TXT, etc.) for our captured names: NXDOMAIN-ish
		// with 0 answers. Browsers typically don't ask for these for plain
		// HTTP navigation.
		binary.BigEndian.PutUint16(out[6:8], 0) // ANCOUNT
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)
	}

	return out, nil
}

// forward sends req to upstreamAddr over UDP and returns the reply. Times
// out after the given duration.
func forward(upstreamAddr string, req []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", upstreamAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
