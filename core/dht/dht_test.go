package dht

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// idFromString hashes a string to produce a deterministic NodeID.
// Useful for writing readable tests.
func idFromString(s string) NodeID {
	return sha256.Sum256([]byte(s))
}

// idFromBits parses a string like "11010..." into a NodeID. Padding zeros
// to 256 bits. Lets us write distance/prefix tests with explicit bit patterns.
func idFromBits(bits string) NodeID {
	bits = strings.ReplaceAll(bits, " ", "")
	for len(bits) < IDSize*8 {
		bits += "0"
	}
	var id NodeID
	for i := 0; i < IDSize; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] == '1' {
				b |= 1 << (7 - j)
			}
		}
		id[i] = b
	}
	return id
}

// --- NodeID ---

func TestXORSelfIsZero(t *testing.T) {
	id := idFromString("alice")
	x := id.XOR(id)
	for _, b := range x {
		if b != 0 {
			t.Fatal("XOR of an ID with itself should be all zeros")
		}
	}
}

func TestXORIsSymmetric(t *testing.T) {
	a := idFromString("alice")
	b := idFromString("bob")
	if a.XOR(b) != b.XOR(a) {
		t.Fatal("XOR distance must be symmetric")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"00000000", "10000000", 0},
		{"10000000", "11000000", 1},
		{"11110000", "11111000", 4},
		{"11111111", "11111111", IDSize * 8}, // identical
	}
	for _, tc := range cases {
		got := idFromBits(tc.a).CommonPrefixLen(idFromBits(tc.b))
		if got != tc.want {
			t.Errorf("CommonPrefixLen(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDistanceLess(t *testing.T) {
	self := idFromBits("00000000")
	near := idFromBits("00000001") // distance 1 from self
	far := idFromBits("10000000")  // distance 2^255 from self
	if !DistanceLess(self, near, far) {
		t.Errorf("near should be closer to self than far")
	}
	if DistanceLess(self, far, near) {
		t.Errorf("far should not be closer than near")
	}
	if DistanceLess(self, near, near) {
		t.Errorf("equal distances should not be 'less than'")
	}
}

func TestIDFromHexRoundtrip(t *testing.T) {
	id := idFromString("hello")
	parsed, err := IDFromHex(id.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equal(id) {
		t.Fatal("id roundtrip mismatch")
	}
}

// --- RoutingTable ---

func TestUpdateAndSize(t *testing.T) {
	rt := NewRoutingTable(idFromString("self"))
	if rt.Size() != 0 {
		t.Fatal("new table should be empty")
	}

	rt.Update(Contact{ID: idFromString("a"), Address: "1.2.3.4:9000"})
	rt.Update(Contact{ID: idFromString("b"), Address: "1.2.3.5:9000"})

	if rt.Size() != 2 {
		t.Errorf("size = %d, want 2", rt.Size())
	}
}

func TestUpdateIgnoresSelf(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)
	rt.Update(Contact{ID: self, Address: "127.0.0.1:9000"})
	if rt.Size() != 0 {
		t.Errorf("self should never be added to its own routing table, size = %d", rt.Size())
	}
}

func TestUpdateIsIdempotent(t *testing.T) {
	rt := NewRoutingTable(idFromString("self"))
	c := Contact{ID: idFromString("a"), Address: "1.2.3.4:9000"}
	rt.Update(c)
	rt.Update(c)
	rt.Update(c)
	if rt.Size() != 1 {
		t.Errorf("repeated Update of same ID should not duplicate, size = %d", rt.Size())
	}
}

func TestRemove(t *testing.T) {
	rt := NewRoutingTable(idFromString("self"))
	a := Contact{ID: idFromString("a"), Address: "1.2.3.4:9000"}
	b := Contact{ID: idFromString("b"), Address: "1.2.3.5:9000"}
	rt.Update(a)
	rt.Update(b)
	rt.Remove(a.ID)
	if rt.Size() != 1 {
		t.Errorf("after remove, size = %d, want 1", rt.Size())
	}
	for _, c := range rt.All() {
		if c.ID.Equal(a.ID) {
			t.Error("removed contact still present")
		}
	}
}

func TestBucketCapAtK(t *testing.T) {
	// Force every contact into the same bucket by giving them all the same
	// CommonPrefixLen with self. We do this by deriving them from self with
	// only the last byte changed.
	self := idFromBits(strings.Repeat("0", 256))
	rt := NewRoutingTable(self)

	for i := 0; i < K+5; i++ {
		var id NodeID
		// Differ from self in the very first bit so they all share bucket 0.
		id[0] = 0x80
		// Use the last few bytes for variation so each is unique.
		id[IDSize-1] = byte(i)
		rt.Update(Contact{ID: id, Address: fmt.Sprintf("10.0.0.%d:9000", i)})
	}
	if rt.Size() > K {
		t.Errorf("bucket should cap at %d contacts, got %d", K, rt.Size())
	}
}

func TestClosestOrdersByDistance(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)

	// Add 10 random contacts.
	for i := 0; i < 10; i++ {
		rt.Update(Contact{
			ID:      idFromString(fmt.Sprintf("peer-%d", i)),
			Address: fmt.Sprintf("10.0.0.%d:9000", i),
		})
	}

	target := idFromString("target")
	closest := rt.Closest(target, 5)
	if len(closest) != 5 {
		t.Fatalf("got %d contacts, want 5", len(closest))
	}

	// Verify monotonically non-decreasing distance.
	for i := 1; i < len(closest); i++ {
		prev := distanceBigInt(target, closest[i-1].ID)
		curr := distanceBigInt(target, closest[i].ID)
		if prev.Cmp(curr) > 0 {
			t.Errorf("contacts not sorted by distance: %v then %v", prev, curr)
		}
	}
}

func TestClosestNeverIncludesSelf(t *testing.T) {
	self := idFromString("self")
	rt := NewRoutingTable(self)
	rt.Update(Contact{ID: idFromString("a"), Address: "x"})
	rt.Update(Contact{ID: idFromString("b"), Address: "y"})

	for _, c := range rt.Closest(self, 10) {
		if c.ID.Equal(self) {
			t.Fatal("Closest must never return self")
		}
	}
}

func TestClosestHandlesFewerThanRequested(t *testing.T) {
	rt := NewRoutingTable(idFromString("self"))
	rt.Update(Contact{ID: idFromString("a"), Address: "x"})
	got := rt.Closest(idFromString("target"), 100)
	if len(got) != 1 {
		t.Errorf("Closest should return %d contacts, got %d", 1, len(got))
	}
}

// TestDistanceConsistency ensures DistanceLess agrees with big.Int comparison.
// This is a sanity check that our byte-by-byte implementation is correct.
func TestDistanceConsistency(t *testing.T) {
	self := idFromString("self")
	a := idFromString("alpha")
	b := idFromString("beta")

	bigA := distanceBigInt(self, a)
	bigB := distanceBigInt(self, b)

	wantALess := bigA.Cmp(bigB) < 0
	gotALess := DistanceLess(self, a, b)

	if wantALess != gotALess {
		t.Errorf("DistanceLess disagrees with big.Int: got %v, want %v", gotALess, wantALess)
	}
}

// _ keeps math/big imported even if no test uses big.Int directly anymore.
var _ = big.NewInt
