package relay

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TunnelOpenTimeout is how long a DIAL request waits for the registered
// peer to dial back with a TUNNEL.
const TunnelOpenTimeout = 10 * time.Second

// Server is a relay listener. Run one of these on any publicly-reachable
// peer to let NAT-ed peers register through you and be reachable by the
// rest of the network.
type Server struct {
	ln net.Listener

	mu           sync.Mutex
	registrations map[string]*registration // peer-id-hex -> control conn
	pending       map[string]chan net.Conn  // tunnel token -> channel waiting for TUNNEL
	stopped       bool
}

// registration is a live control connection to a registered peer.
type registration struct {
	peerID string
	conn   net.Conn
	out    chan string // queued lines to send (e.g. "OPEN <token>")
}

// NewServer creates a Server. Call Start to begin listening.
func NewServer() *Server {
	return &Server{
		registrations: make(map[string]*registration),
		pending:       make(map[string]chan net.Conn),
	}
}

// Start binds to addr and begins serving. Returns once bound; serving
// runs in a goroutine. Call Stop to shut down.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", addr, err)
	}
	s.ln = ln
	go s.acceptLoop()
	return nil
}

// LocalAddr returns the address actually bound. Useful when starting on
// an ephemeral port (":0") in tests.
func (s *Server) LocalAddr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Stop shuts the listener and tears down every active registration.
func (s *Server) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	regs := make([]*registration, 0, len(s.registrations))
	for _, r := range s.registrations {
		regs = append(regs, r)
	}
	s.mu.Unlock()

	if s.ln != nil {
		s.ln.Close()
	}
	for _, r := range regs {
		r.conn.Close()
	}
}

// RegistrationCount returns the number of currently-registered peers.
// Useful for tests.
func (s *Server) RegistrationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.registrations)
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// handle reads the first line of a new connection and dispatches by
// command type.
func (s *Server) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	// Cap how long we wait for the first line.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := readLine(br)
	if err != nil {
		conn.Close()
		return
	}
	// Clear the deadline now that we have the command.
	_ = conn.SetReadDeadline(time.Time{})

	parts := strings.Fields(line)
	if len(parts) < 1 {
		writeLine(conn, RespErr+" empty command")
		conn.Close()
		return
	}
	switch parts[0] {
	case CmdRegister:
		if len(parts) != 2 {
			writeLine(conn, RespErr+" usage: REGISTER <peer-id>")
			conn.Close()
			return
		}
		s.handleRegister(parts[1], conn, br)
	case CmdDial:
		if len(parts) != 2 {
			writeLine(conn, RespErr+" usage: DIAL <peer-id>")
			conn.Close()
			return
		}
		s.handleDial(parts[1], conn)
	case CmdTunnel:
		if len(parts) != 2 {
			writeLine(conn, RespErr+" usage: TUNNEL <token>")
			conn.Close()
			return
		}
		s.handleTunnel(parts[1], conn)
	default:
		writeLine(conn, RespErr+" unknown command")
		conn.Close()
	}
}

// handleRegister keeps the connection open as the control channel for a
// registered peer. The control channel is used to push "OPEN <token>"
// lines whenever someone DIALs the registered peer.
func (s *Server) handleRegister(peerID string, conn net.Conn, br *bufio.Reader) {
	if !validHexID(peerID) {
		writeLine(conn, RespErr+" bad peer-id")
		conn.Close()
		return
	}

	reg := &registration{
		peerID: peerID,
		conn:   conn,
		out:    make(chan string, 16),
	}

	s.mu.Lock()
	// Replace any prior registration for this peer (only one at a time).
	if old, ok := s.registrations[peerID]; ok {
		old.conn.Close()
	}
	s.registrations[peerID] = reg
	s.mu.Unlock()

	if err := writeLine(conn, RespOK); err != nil {
		s.dropRegistration(reg)
		return
	}

	// Writer goroutine: drain reg.out and send lines to the registered peer.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for line := range reg.out {
			if err := writeLine(conn, line); err != nil {
				return
			}
		}
	}()

	// Reader goroutine on the same conn: detect peer disconnect.
	// We don't expect more lines from the registered peer, but reading
	// is the cheapest way to notice EOF.
	for {
		_, err := br.ReadByte()
		if err != nil {
			break
		}
	}
	s.dropRegistration(reg)
	close(reg.out)
	<-writerDone
}

// dropRegistration removes a registration if it's still the current one.
func (s *Server) dropRegistration(reg *registration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.registrations[reg.peerID]; ok && cur == reg {
		delete(s.registrations, reg.peerID)
	}
	reg.conn.Close()
}

// handleDial finds a registered peer, asks them to open a tunnel, then
// pipes bytes between the dialer's connection and the peer's tunnel
// connection.
func (s *Server) handleDial(peerID string, dialerConn net.Conn) {
	s.mu.Lock()
	reg, ok := s.registrations[peerID]
	s.mu.Unlock()
	if !ok {
		writeLine(dialerConn, RespErr+" peer not registered")
		dialerConn.Close()
		return
	}

	token, err := newToken()
	if err != nil {
		writeLine(dialerConn, RespErr+" internal")
		dialerConn.Close()
		return
	}

	tunnelCh := make(chan net.Conn, 1)
	s.mu.Lock()
	s.pending[token] = tunnelCh
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, token)
		s.mu.Unlock()
	}()

	// Push an OPEN to the registered peer.
	select {
	case reg.out <- PushOpen + " " + token:
	default:
		writeLine(dialerConn, RespErr+" peer queue full")
		dialerConn.Close()
		return
	}

	// Wait for the registered peer to dial back with TUNNEL <token>.
	var tunnelConn net.Conn
	select {
	case tunnelConn = <-tunnelCh:
	case <-time.After(TunnelOpenTimeout):
		writeLine(dialerConn, RespErr+" timeout")
		dialerConn.Close()
		return
	}

	// Tell both sides we're good.
	if err := writeLine(dialerConn, RespOK); err != nil {
		dialerConn.Close()
		tunnelConn.Close()
		return
	}
	if err := writeLine(tunnelConn, RespOK); err != nil {
		dialerConn.Close()
		tunnelConn.Close()
		return
	}

	// Pipe bytes both ways. Either side closing tears down both.
	pipe(dialerConn, tunnelConn)
}

// handleTunnel matches a TUNNEL <token> with a waiting DIAL.
func (s *Server) handleTunnel(token string, tunnelConn net.Conn) {
	s.mu.Lock()
	ch, ok := s.pending[token]
	s.mu.Unlock()
	if !ok {
		writeLine(tunnelConn, RespErr+" bad token")
		tunnelConn.Close()
		return
	}
	// Hand off to the waiting DIAL handler. It will write OK and start piping.
	select {
	case ch <- tunnelConn:
		// success; the DIAL handler now owns this conn
	default:
		writeLine(tunnelConn, RespErr+" race")
		tunnelConn.Close()
	}
}

// pipe forwards bytes between two connections until either closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go copy(a, b)
	go copy(b, a)
	<-done
	a.Close()
	b.Close()
}

// newToken returns a 16-byte random hex token, used to match a TUNNEL
// connection back to the originating DIAL. 16 bytes = 128 bits of
// entropy; collision-free in any realistic relay.
func newToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validHexID reports whether s looks like a 64-char hex string (the
// shape of a NodeID / peer ID).
func validHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
