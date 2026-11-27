// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rfc6962_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
)

// This file pins the hash-domain-separation contract of RFC 6962 at the
// primitive layer:
//
//   - the empty tree, a leaf commitment, and an interior node occupy distinct
//     hash domains;
//   - the leaf/node prefixes (0x00 / 0x01) disambiguate roles even when the
//     remaining preimage bytes are identical;
//   - left/right order matters;
//   - the optimized SHA-256 implementation and the generic hashing path
//     produce identical digests.
//
// The expected values below are computed directly from the RFC 6962 wire
// format with the standard library, so they do not share code with the
// implementation under test.

const (
	rsWantEmptyRoot = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	rsWantEmptyLeaf = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
)

func rsMustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// rsGenericNode256 is the straightforward generic RFC 6962 interior-node
// construction H(0x01 || l || r), written through the streaming hash API. It
// intentionally does not call rfc6962.Hasher.HashChildren or reference its
// prefix constants, so it stays an independent oracle for the fast path.
func rsGenericNode256(t *testing.T, l, r []byte) []byte {
	t.Helper()
	h := sha256.New()
	if _, err := h.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write(l); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write(r); err != nil {
		t.Fatal(err)
	}
	return h.Sum(nil)
}

func TestRoleSeparationPrefixConstants(t *testing.T) {
	if got, want := rfc6962.RFC6962LeafHashPrefix, 0; got != want {
		t.Errorf("RFC6962LeafHashPrefix = %d, want %d", got, want)
	}
	if got, want := rfc6962.RFC6962NodeHashPrefix, 1; got != want {
		t.Errorf("RFC6962NodeHashPrefix = %d, want %d", got, want)
	}
}

func TestRoleSeparationEmptyTreeAndEmptyLeafAreDifferentDomains(t *testing.T) {
	h := rfc6962.DefaultHasher

	wantEmptyRoot := rsMustHex(t, rsWantEmptyRoot)
	if got := h.EmptyRoot(); !bytes.Equal(got, wantEmptyRoot) {
		t.Errorf("EmptyRoot() = %x, want %x (SHA-256 of the empty string)", got, wantEmptyRoot)
	}
	if got := sha256.Sum256(nil); !bytes.Equal(h.EmptyRoot(), got[:]) {
		t.Error("EmptyRoot() must equal sha256.Sum256(nil)")
	}

	wantEmptyLeaf := rsMustHex(t, rsWantEmptyLeaf)
	if got := h.HashLeaf(nil); !bytes.Equal(got, wantEmptyLeaf) {
		t.Errorf("HashLeaf(nil) = %x, want %x (SHA-256 of 0x00)", got, wantEmptyLeaf)
	}

	// The empty tree head must never be interchangeable with the commitment to
	// an empty leaf.
	if bytes.Equal(h.EmptyRoot(), h.HashLeaf(nil)) {
		t.Fatal("empty-tree root and empty-leaf hash are identical; hash domains are not separated")
	}

	// Nor may the empty root collide with an interior-node digest built from
	// empty-ish children.
	if node := h.HashChildren(h.EmptyRoot(), h.EmptyRoot()); bytes.Equal(node, h.EmptyRoot()) {
		t.Error("HashChildren(emptyRoot, emptyRoot) unexpectedly equals the empty-tree root")
	}
}

func TestRoleSeparationSameBytesDifferentRoles(t *testing.T) {
	h := rfc6962.DefaultHasher

	// Two distinct, fixed 32-byte child hashes.
	l := sha256.Sum256([]byte("left child"))
	r := sha256.Sum256([]byte("right child"))
	lb, rb := l[:], r[:]

	node := h.HashChildren(lb, rb)
	if len(node) != h.Size() {
		t.Fatalf("HashChildren returned %d bytes, want %d", len(node), h.Size())
	}

	// The interior digest is H(0x01 || l || r). Hashing the exact same tail
	// bytes (l || r) through the leaf domain (0x00) must give another value.
	tail := append(append([]byte{}, lb...), rb...)
	if got := h.HashLeaf(tail); bytes.Equal(got, node) {
		t.Error("H(0x00 || l || r) == H(0x01 || l || r); leaf/node domains are not separated")
	}

	// Even feeding the literal interior preimage (0x01 || l || r) to HashLeaf
	// must not reproduce the interior digest, because the leaf prefix is
	// prepended again.
	internalPreimage := append([]byte{0x01}, tail...)
	if got := h.HashLeaf(internalPreimage); bytes.Equal(got, node) {
		t.Error("HashLeaf(0x01 || l || r) == HashChildren(l, r); an internal node can impersonate a leaf")
	}

	// Committing to the internal digest itself as leaf data stays in another
	// domain too.
	if got := h.HashLeaf(node); bytes.Equal(got, node) {
		t.Error("HashLeaf(internalDigest) == internalDigest")
	}

	// Treating the concatenated children as one leaf is the classic confused
	// construction; it must differ from the interior node.
	if got := h.HashLeaf(tail); bytes.Equal(got, node) {
		t.Error("HashLeaf(l || r) == HashChildren(l, r)")
	}

	// Left/right order is part of the commitment.
	if swapped := h.HashChildren(rb, lb); bytes.Equal(swapped, node) {
		t.Error("HashChildren(l, r) == HashChildren(r, l); child order is not reflected")
	}
}

func TestRoleSeparationFastPathMatchesGenericPath(t *testing.T) {
	h := rfc6962.DefaultHasher

	// A sequence of deterministic, distinct 32-byte hashes. Every pair hits
	// the SHA-256 fast path in HashChildren.
	seeds := make([][]byte, 0, 8)
	cur := sha256.Sum256([]byte("fast-path-seed"))
	for range 8 {
		b := append([]byte(nil), cur[:]...)
		seeds = append(seeds, b)
		cur = sha256.Sum256(b)
	}

	for i := 0; i+1 < len(seeds); i++ {
		l, r := seeds[i], seeds[i+1]

		got := h.HashChildren(l, r)

		// Independent one-shot construction of 0x01 || l || r.
		pre := make([]byte, 0, 1+len(l)+len(r))
		pre = append(pre, 0x01)
		pre = append(pre, l...)
		pre = append(pre, r...)
		oneShot := sha256.Sum256(pre)

		if !bytes.Equal(got, oneShot[:]) {
			t.Errorf("pair %d: HashChildren fast path = %x, want RFC digest %x", i, got, oneShot)
		}
		if streamed := rsGenericNode256(t, l, r); !bytes.Equal(got, streamed) {
			t.Errorf("pair %d: fast path %x != generic streaming path %x", i, got, streamed)
		}
	}

	// Zero hashes must take the same path and match the RFC vector
	// H(0x01 || 0^32 || 0^32).
	zeros := make([]byte, sha256.Size)
	got := h.HashChildren(zeros, zeros)
	want := rsGenericNode256(t, zeros, zeros)
	if !bytes.Equal(got, want) {
		t.Errorf("zero pair: fast path %x != generic path %x", got, want)
	}
}

func TestRoleSeparationGenericBranchForNonCanonicalLengths(t *testing.T) {
	h := rfc6962.DefaultHasher
	// Children whose length is not sha256.Size force HashChildren through the
	// generic t.New() write path rather than hashChildren256.
	for _, n := range []int{0, 1, 31, sha256.Size + 1, 64} {
		l := bytes.Repeat([]byte{0xaa}, n)
		r := bytes.Repeat([]byte{0xbb}, n)
		got := h.HashChildren(l, r)
		want := rsGenericNode256(t, l, r)
		if !bytes.Equal(got, want) {
			t.Errorf("len=%d: generic-branch digest %x != independent RFC digest %x", n, got, want)
		}
	}
}

func TestRoleSeparationGenericHasherOtherAlgorithm(t *testing.T) {
	// The generic implementation must also be correct for a non-SHA-256 hash,
	// which never enters the fast path.
	h := rfc6962.New(crypto.SHA512)
	if got, want := h.Size(), sha512.Size; got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}

	l := bytes.Repeat([]byte{0x10}, sha512.Size)
	r := bytes.Repeat([]byte{0x20}, sha512.Size)
	got := h.HashChildren(l, r)

	hh := sha512.New()
	hh.Write([]byte{0x01})
	hh.Write(l)
	hh.Write(r)
	want := hh.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("SHA-512 HashChildren = %x, want %x", got, want)
	}

	empty := sha512.Sum512(nil)
	if !bytes.Equal(h.EmptyRoot(), empty[:]) {
		t.Errorf("SHA-512 EmptyRoot = %x, want %x", h.EmptyRoot(), empty)
	}
}
