// Package relay implements NAT traversal for AltNet via "rendezvous"
// peers that have a public IP. A peer behind NAT cannot accept incoming
// TCP -- but it CAN dial out. So:
//
//   1. The NAT-ed peer A dials a publicly-reachable relay R and tells
//      R "I'm peer-id <X>; please be my relay."
//   2. R remembers that connection as a control channel to A.
//   3. When some other peer B wants to reach A, B dials R and says
//      "open a tunnel to peer-id <X>."
//   4. R sends a control message over the existing channel to A,
//      asking A to dial R back with a one-time tunnel token.
//   5. A dials R (outbound, NAT-friendly) and identifies itself with
//      the token.
//   6. R now holds two TCP sockets -- one to B, one to A -- and pipes
//      bytes between them.
//
// From A's and B's perspective, once the tunnel is established, the
// connection looks like a normal peer dial. They run the secure
// handshake and the rest of the AltNet protocol over it. The relay
// never sees plaintext: end-to-end encryption survives intact because
// the relay only forwards opaque ciphertext.
//
// What the relay CAN do is drop or stall traffic (DoS), but it cannot
// impersonate A or eavesdrop. Multiple relays are easy to run, and
// bad relays get ignored when peers prefer working ones.
//
// Wire protocol on relay-port connections:
//
//   First line is ASCII, terminated by '\n'. After the first line:
//
//     - REGISTER <peer-id-hex>            -- A registers as relay-able
//       Reply (one line):
//         OK
//         (followed by zero or more "OPEN <token>" pushes from R)
//
//     - DIAL <peer-id-hex>                -- B asks for a tunnel to A
//       Reply (one line):
//         OK             -- tunnel established; raw bytes follow
//         ERR <message>  -- failure (no such peer, busy, etc.)
//
//     - TUNNEL <token>                    -- A's tunnel-init connection
//       Reply (one line):
//         OK             -- raw bytes follow
//         ERR <message>  -- bad token
//
// Lines are bounded to MaxLineSize bytes for safety; anything bigger
// gets rejected.
package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxLineSize bounds the length of a control line. Real lines top out
// around 80 bytes (command + 64-char peer ID + space).
const MaxLineSize = 256

// Command names on the wire.
const (
	CmdRegister = "REGISTER"
	CmdDial     = "DIAL"
	CmdTunnel   = "TUNNEL"
	RespOK      = "OK"
	RespErr     = "ERR"
	PushOpen    = "OPEN" // R -> A: "please open tunnel <token>"
)

// readLine reads a newline-terminated control line of at most MaxLineSize
// bytes from r. The newline is stripped.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if err == io.EOF && line != "" {
			// Tolerate missing trailing newline at EOF.
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	if len(line) > MaxLineSize {
		return "", errors.New("relay: line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// writeLine writes a single CRLF-terminated control line to w.
func writeLine(w io.Writer, line string) error {
	if len(line) > MaxLineSize {
		return errors.New("relay: line too long")
	}
	_, err := fmt.Fprintf(w, "%s\n", line)
	return err
}
