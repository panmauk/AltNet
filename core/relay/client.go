package relay

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DialTimeout is how long DialVia waits for the relay to set up a tunnel.
const DialTimeout = 15 * time.Second

// DialVia opens a tunnel through the relay at relayAddr to the registered
// peer with peerID. Returns a net.Conn that, from the caller's
// perspective, is a TCP connection to the target peer -- bytes written
// flow through the relay to the peer, and vice versa.
//
// Use this when the target peer is behind NAT and not directly dialable.
// The caller can then run the secure handshake and rest of the AltNet
// peer protocol on this conn unchanged.
func DialVia(relayAddr, peerID string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", relayAddr, DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", relayAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(DialTimeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if err := writeLine(conn, CmdDial+" "+peerID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay write DIAL: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := readLine(br)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay read response: %w", err)
	}
	if !strings.HasPrefix(resp, RespOK) {
		conn.Close()
		return nil, fmt.Errorf("relay refused: %s", resp)
	}

	// Clear deadline; the conn now belongs to the caller.
	_ = conn.SetDeadline(time.Time{})

	// If bufio buffered any post-OK bytes (shouldn't happen in normal
	// flow, but possible if the registered peer sent something fast),
	// wrap the conn so the caller sees them on the next Read.
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		_, _ = br.Read(buffered)
		return &prefixConn{Conn: conn, prefix: buffered}, nil
	}
	return conn, nil
}

// prefixConn wraps a net.Conn but returns prefix bytes on the first
// Read(s) before falling through to the underlying conn.
type prefixConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	p.mu.Lock()
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()
	return p.Conn.Read(b)
}

// AcceptedTunnel is a freshly-accepted tunnel from a relay, plus enough
// metadata for the peer layer to treat it as an inbound connection.
type AcceptedTunnel struct {
	Conn net.Conn
}

// Client maintains a persistent control connection to a relay. While
// the control connection is open, the relay can ask us to open tunnels
// (one per incoming DIAL on the relay). Each tunnel ends up in the
// Tunnels channel, and the caller (typically the peer accept loop)
// treats each one as an incoming peer connection.
type Client struct {
	relayAddr string
	peerID    string

	// Tunnels yields each accepted tunnel as a fresh net.Conn. The peer
	// layer reads from this channel and runs the inbound side of the
	// secure handshake on each.
	Tunnels chan net.Conn

	mu         sync.Mutex
	stop       chan struct{}
	stopped    bool
	activeConn net.Conn // current control connection, if any; nil between connect attempts
	wg         sync.WaitGroup
}

// NewClient creates a Client that, when Run, will register peerID with
// the relay at relayAddr and surface incoming tunnels on the Tunnels
// channel. Caller is responsible for ranging over Tunnels in a goroutine.
func NewClient(relayAddr, peerID string) *Client {
	return &Client{
		relayAddr: relayAddr,
		peerID:    peerID,
		Tunnels:   make(chan net.Conn, 16),
		stop:      make(chan struct{}),
	}
}

// Run registers with the relay and processes OPEN pushes. Reconnects
// with exponential backoff if the relay drops us. Returns when Stop is
// called.
//
// Callers typically launch this in a goroutine and consume from
// c.Tunnels.
func (c *Client) Run() {
	c.wg.Add(1)
	defer c.wg.Done()

	backoff := time.Second
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		if err := c.runOnce(); err != nil {
			// Reconnect after backoff. Cap at 1 minute.
			t := time.NewTimer(backoff)
			select {
			case <-c.stop:
				t.Stop()
				return
			case <-t.C:
			}
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
			continue
		}
		backoff = time.Second
	}
}

// runOnce holds a single control connection until it dies. Returns the
// error that killed it (or nil if Stop was called cleanly).
func (c *Client) runOnce() error {
	conn, err := net.DialTimeout("tcp", c.relayAddr, DialTimeout)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		conn.Close()
		return nil
	}
	c.activeConn = conn
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.activeConn = nil
		c.mu.Unlock()
		conn.Close()
	}()

	if err := writeLine(conn, CmdRegister+" "+c.peerID); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	resp, err := readLine(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, RespOK) {
		return fmt.Errorf("relay refused REGISTER: %s", resp)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Now we read OPEN <token> pushes from the relay. For each one, we
	// dial the relay back with TUNNEL <token> and surface the resulting
	// conn on Tunnels.
	for {
		select {
		case <-c.stop:
			return nil
		default:
		}
		line, err := readLine(br)
		if err != nil {
			return err
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == PushOpen {
			token := parts[1]
			// Open the tunnel in a goroutine so we don't block the read loop.
			go c.openTunnel(token)
		}
		// Unknown lines are ignored; future protocol additions go here.
	}
}

func (c *Client) openTunnel(token string) {
	tconn, err := net.DialTimeout("tcp", c.relayAddr, DialTimeout)
	if err != nil {
		return
	}
	if err := tconn.SetDeadline(time.Now().Add(DialTimeout)); err != nil {
		tconn.Close()
		return
	}
	if err := writeLine(tconn, CmdTunnel+" "+token); err != nil {
		tconn.Close()
		return
	}
	br := bufio.NewReader(tconn)
	resp, err := readLine(br)
	if err != nil {
		tconn.Close()
		return
	}
	if !strings.HasPrefix(resp, RespOK) {
		tconn.Close()
		return
	}
	_ = tconn.SetDeadline(time.Time{})

	final := net.Conn(tconn)
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		_, _ = br.Read(buffered)
		final = &prefixConn{Conn: tconn, prefix: buffered}
	}

	// Surface the conn. If the consumer is slow / not running, drop the
	// tunnel rather than block.
	select {
	case c.Tunnels <- final:
	case <-c.stop:
		final.Close()
	default:
		final.Close()
	}
}

// Stop signals the client to disconnect and stops accepting new tunnels.
// Blocks until Run returns.
func (c *Client) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	close(c.stop)
	// Close the active control conn if any so any blocking Read in
	// runOnce returns immediately.
	conn := c.activeConn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	c.wg.Wait()
}
