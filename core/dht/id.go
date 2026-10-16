// Package dht implements a Kademlia-style distributed hash table.
//
// The DHT lets a peer find any other peer (or any piece of content) in a
// network of millions of nodes by querying a small number (O(log n)) of
// other peers. There is no central index — the routing information is
// spread across all participants.
//
// Files in this package:
//
//	id.go       — NodeID type and XOR distance
//	routing.go  — k-bucket routing table
//	dht.go      — message handling and lookup (added in a later step)
package dht

import (
	"encoding/hex"
	"errors"
	"math/big"
)

// IDSize is the length of a NodeID in bytes. We use 256-bit IDs because
// peer IDs in this system are SHA-256 hashes of public keys.
const IDSize = 32

// NodeID is a fixed-size, immutable identifier for a peer in the DHT.
// Two peers having the same NodeID is cryptographically negligible.
type NodeID [IDSize]byte

// IDFromHex parses a hex-encoded NodeID such as the one returned by
// crypto.PublicKeyToID.
func IDFromHex(s string) (NodeID, error) {
	var id NodeID
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(raw) != IDSize {
		return id, errors.New("dht: id must be 32 bytes")
	}
	copy(id[:], raw)
	return id, nil
}

// Hex returns the lowercase hex representation of the ID.
func (n NodeID) Hex() string { return hex.EncodeToString(n[:]) }

// String returns a short prefix for readable logs.
func (n NodeID) String() string { return n.Hex()[:8] }

// Equal reports whether two NodeIDs are the same.
func (n NodeID) Equal(other NodeID) bool {
	for i := 0; i < IDSize; i++ {
		if n[i] != other[i] {
			return false
		}
	}
	return true
}

// XOR returns a NodeID where each byte is n[i] XOR other[i].
// In Kademlia "distance" between two IDs is defined as their XOR.
//
// This is unusual but elegant: XOR distance is symmetric (d(a,b)=d(b,a)),
// has zero exactly when a=b, and obeys the triangle inequality. It also
// means each bit of the ID partitions the network in half, which is what
// makes routing logarithmic.
func (n NodeID) XOR(other NodeID) NodeID {
	var out NodeID
	for i := 0; i < IDSize; i++ {
		out[i] = n[i] ^ other[i]
	}
	return out
}

// CommonPrefixLen returns the number of leading bits that n and other share.
// This is what tells you which k-bucket a peer belongs in: the bucket index
// is "the position of the first bit where this peer differs from us."
//
//	a = 0b110101...
//	b = 0b110010...
//	         ^ first differing bit at index 3
//	-> common prefix length = 3
//
// Two identical IDs have common prefix length = 8*IDSize.
func (n NodeID) CommonPrefixLen(other NodeID) int {
	for i := 0; i < IDSize; i++ {
		x := n[i] ^ other[i]
		if x == 0 {
			continue
		}
		// Count leading zeros within this byte.
		for j := 0; j < 8; j++ {
			if x&(1<<(7-j)) != 0 {
				return i*8 + j
			}
		}
	}
	return IDSize * 8
}

// DistanceLess reports whether the XOR distance from self to a is strictly
// less than the XOR distance from self to b. This is the comparator used to
// pick "the closest known peer to some target."
//
// Implemented as bytewise comparison of the two XOR results, which works
// because XOR distances are interpreted as 256-bit unsigned integers in
// big-endian form.
func DistanceLess(self, a, b NodeID) bool {
	for i := 0; i < IDSize; i++ {
		da := self[i] ^ a[i]
		db := self[i] ^ b[i]
		if da != db {
			return da < db
		}
	}
	return false
}

// distanceBigInt returns the XOR distance between two IDs as a big.Int.
// Used by tests and for human-readable distance output. Production code
// should prefer DistanceLess to avoid allocations.
func distanceBigInt(a, b NodeID) *big.Int {
	x := a.XOR(b)
	return new(big.Int).SetBytes(x[:])
}
