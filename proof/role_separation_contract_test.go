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

// Package proof_test contains end-to-end contract tests for hash domain
// separation across the empty tree, leaf commitments, tree heads and
// inclusion/consistency proof verification.
package proof_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"testing"

	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// rsLeafPrefix and rsNodePrefix are the RFC 6962 domain-separation bytes,
// hardcoded here (rather than referenced from rfc6962) so the test remains an
// independent specification oracle.
const (
	rsLeafPrefix = byte(0x00)
	rsNodePrefix = byte(0x01)
)

// rsGenericHasher is a from-scratch generic RFC 6962 LogHasher built directly
// on crypto/sha256's streaming interface. It never uses the optimized fast
// path inside rfc6962.Hasher, which lets us compare the two implementations on
// whole legal logs.
type rsGenericHasher struct{}

func (rsGenericHasher) EmptyRoot() []byte {
	s := sha256.Sum256(nil)
	return s[:]
}

func (rsGenericHasher) HashLeaf(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rsLeafPrefix})
	h.Write(leaf)
	return h.Sum(nil)
}

func (rsGenericHasher) HashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rsNodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func (rsGenericHasher) Size() int { return sha256.Size }

var _ merkle.LogHasher = rsGenericHasher{}

// rsSpecLeaf / rsSpecNode / rsSpecRoot are an independent implementation of
// the RFC 6962 Merkle Tree Hash recursion. They deliberately use only the
// standard library and the hardcoded prefixes above.
func rsSpecLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rsLeafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

func rsSpecNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rsNodePrefix})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func rsSpecRoot(entries [][]byte) []byte {
	switch n := len(entries); {
	case n == 0:
		s := sha256.Sum256(nil)
		return s[:]
	case n == 1:
		return rsSpecLeaf(entries[0])
	default:
		k := 1 << (bits.Len(uint(n-1)) - 1) // largest power of two < n
		return rsSpecNode(rsSpecRoot(entries[:k]), rsSpecRoot(entries[k:]))
	}
}

func rsEntries(n int) [][]byte {
	out := make([][]byte, n)
	for i := range n {
		out[i] = []byte(fmt.Sprintf("role-separated-leaf-%02d", i))
	}
	return out
}

// rsCompactRoot computes the log root through the generic compact-range merge
// path (compact.RangeFactory), which only knows HashChildren and treats every
// appended hash as a level-0 node.
func rsCompactRoot(t *testing.T, h merkle.LogHasher, entries [][]byte) []byte {
	t.Helper()
	f := &compact.RangeFactory{Hash: h.HashChildren}
	rng := f.NewEmptyRange(0)
	for _, e := range entries {
		if err := rng.Append(h.HashLeaf(e), nil); err != nil {
			t.Fatalf("Range.Append: %v", err)
		}
	}
	root, err := rng.GetRootHash(nil)
	if err != nil {
		t.Fatalf("GetRootHash: %v", err)
	}
	if len(entries) == 0 {
		if root != nil {
			t.Fatalf("empty compact range root = %x, want nil", root)
		}
		return h.EmptyRoot()
	}
	return root
}

// rsTree builds a reference testonly.Tree from the given entries.
func rsTree(t *testing.T, h merkle.LogHasher, entries [][]byte) *testonly.Tree {
	t.Helper()
	tr := testonly.New(h)
	tr.AppendData(entries...)
	return tr
}

// rsInternalNodes enumerates every complete interior node (level >= 1)
// actually present in a tree of size n.
func rsInternalNodes(t *testing.T, h merkle.LogHasher, entries [][]byte, n uint64) [][]byte {
	t.Helper()
	tr := rsTree(t, h, entries[:n])
	var nodes [][]byte
	for k := uint64(1); (uint64(1) << k) <= n; k++ {
		size := uint64(1) << k
		for start := uint64(0); start+size <= n; start += size {
			nodes = append(nodes, tr.SubtreeHashAt(start, start+size))
		}
	}
	return nodes
}

// TestRoleSeparationEmptyTreeBoundary pins the empty-tree domain and checks
// that proof verification cannot be talked into treating an empty-leaf hash or
// an interior digest as the empty tree head.
func TestRoleSeparationEmptyTreeBoundary(t *testing.T) {
	h := rfc6962.DefaultHasher
	emptyRoot := h.EmptyRoot()
	emptyLeaf := h.HashLeaf(nil)

	if !bytes.Equal(emptyRoot, testonly.EmptyRootHash()) {
		t.Fatalf("EmptyRoot = %x, want testonly gold %x", emptyRoot, testonly.EmptyRootHash())
	}
	if bytes.Equal(emptyRoot, emptyLeaf) {
		t.Fatal("empty-tree root equals HashLeaf(empty); domains merged")
	}
	interior := h.HashChildren(emptyLeaf, emptyLeaf)

	// There is no inclusion proof for any leaf in a size-0 tree.
	for _, leafHash := range [][]byte{nil, emptyLeaf, interior} {
		if err := proof.VerifyInclusion(h, 0, 0, leafHash, nil, emptyRoot); err == nil {
			t.Errorf("VerifyInclusion(index=0,size=0,leaf=%x) succeeded; want error", leafHash)
		}
	}

	// Consistency proofs out of size 0 do not exist.
	if err := proof.VerifyConsistency(h, 0, 1, nil, emptyRoot, emptyRoot); err == nil {
		t.Error("VerifyConsistency(size1=0) succeeded; want 'meaningless' error")
	}

	// An empty subtree [0,0) is anchored to the empty-tree root only.
	if err := proof.VerifySubtreeConsistency(h, 0, 0, 0, nil, emptyRoot, emptyRoot); err != nil {
		t.Errorf("empty subtree with EmptyRoot rejected: %v", err)
	}
	for name, wrongSubRoot := range map[string][]byte{
		"empty leaf hash": emptyLeaf,
		"interior digest": interior,
	} {
		if err := proof.VerifySubtreeConsistency(h, 0, 0, 0, nil, wrongSubRoot, emptyRoot); err == nil {
			t.Errorf("empty subtree accepted a %s (%x) as its root; trust boundary broken", name, wrongSubRoot)
		}
		if _, err := proof.RootFromSubtreeConsistencyProof(h, 0, 0, 0, nil, wrongSubRoot); err == nil {
			t.Errorf("RootFromSubtreeConsistencyProof accepted %s as empty subtree root", name)
		}
	}

	// The same anchoring applies to an empty subtree in the middle of a larger
	// tree: [4,4) inside size 8 must still claim the empty root.
	if err := proof.VerifySubtreeConsistency(h, 4, 4, 8, nil, emptyRoot, emptyRoot); err != nil {
		t.Errorf("empty [4,4) subtree with EmptyRoot rejected: %v", err)
	}
	if err := proof.VerifySubtreeConsistency(h, 4, 4, 8, nil, emptyLeaf, emptyRoot); err == nil {
		t.Error("empty [4,4) subtree accepted HashLeaf(nil) as its root")
	}
}

// TestRoleSeparationShapesOrderAndCategory checks that roots of the same batch
// of leaves across the different RFC 6962 tree shapes are exactly the ones
// dictated by left/right order and the leaf-vs-interior category prefixes.
func TestRoleSeparationShapesOrderAndCategory(t *testing.T) {
	h := rfc6962.DefaultHasher

	// Gold RFC vectors for the fixed LeafInputs batch, sizes 0..8.
	goldRoots := testonly.RootHashes()
	inputs := testonly.LeafInputs()
	if len(goldRoots) != len(inputs)+1 {
		t.Fatalf("gold roots count %d, want %d", len(goldRoots), len(inputs)+1)
	}
	for n := 0; n <= len(inputs); n++ {
		batch := inputs[:n]
		if got := rsSpecRoot(batch); !bytes.Equal(got, goldRoots[n]) {
			t.Errorf("spec root size %d = %x, want gold %x", n, got, goldRoots[n])
		}
		tr := rsTree(t, h, batch)
		if got := tr.Hash(); !bytes.Equal(got, goldRoots[n]) {
			t.Errorf("Tree root size %d = %x, want gold %x", n, got, goldRoots[n])
		}
		if got := rsCompactRoot(t, h, batch); !bytes.Equal(got, goldRoots[n]) {
			t.Errorf("compact root size %d = %x, want gold %x", n, got, goldRoots[n])
		}
	}

	// Explicit 4-leaf shape.
	a, b, c, d := []byte("a"), []byte("b"), []byte("c"), []byte("d")
	la, lb, lc, ld := h.HashLeaf(a), h.HashLeaf(b), h.HashLeaf(c), h.HashLeaf(d)
	canonical := h.HashChildren(h.HashChildren(la, lb), h.HashChildren(lc, ld))
	if got := rsSpecRoot([][]byte{a, b, c, d}); !bytes.Equal(got, canonical) {
		t.Errorf("4-leaf canonical root %x != spec %x", canonical, got)
	}

	for name, other := range map[string][]byte{
		"swapped children at root": h.HashChildren(h.HashChildren(lc, ld), h.HashChildren(la, lb)),
		"swapped a/b order":        h.HashChildren(h.HashChildren(lb, la), h.HashChildren(lc, ld)),
		"right-leaning shape":      h.HashChildren(la, h.HashChildren(lb, h.HashChildren(lc, ld))),
		"leaf category at node": func() []byte {
			// Pair (a,b) "hashed as a leaf" instead of as an interior node.
			fakePair := h.HashLeaf(append(append([]byte{}, la...), lb...))
			return h.HashChildren(fakePair, h.HashChildren(lc, ld))
		}(),
	} {
		if bytes.Equal(other, canonical) {
			t.Errorf("%s produced the canonical root; order/category not enforced", name)
		}
	}

	// Verification enforces the same left/right orientation. In a size-2 tree
	// the proof for index 0 is [HashLeaf(b)] and chains as H(leaf, sibling).
	root2 := h.HashChildren(la, lb)
	if err := proof.VerifyInclusion(h, 0, 2, la, [][]byte{lb}, root2); err != nil {
		t.Fatalf("valid left-leaf proof rejected: %v", err)
	}
	if err := proof.VerifyInclusion(h, 1, 2, lb, [][]byte{la}, root2); err != nil {
		t.Fatalf("valid right-leaf proof rejected: %v", err)
	}
	// Claiming la sits at right-child index 1 with lb as its left sibling
	// computes H(lb, la), which must not match H(la, lb).
	if err := proof.VerifyInclusion(h, 1, 2, la, [][]byte{lb}, root2); err == nil {
		t.Error("index/order-confused proof verified against H(la, lb)")
	}

	// Reversing the batch yields a different committed head whose proofs do not
	// verify under the original head.
	reversed := [][]byte{d, c, b, a}
	revTree := rsTree(t, h, reversed)
	if bytes.Equal(revTree.Hash(), canonical) {
		t.Fatal("reversed batch has the same root as the original order")
	}
	p, err := revTree.InclusionProof(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyInclusion(h, 0, 4, revTree.LeafHash(0), p, canonical); err == nil {
		t.Error("proof from reversed leaf order verified under the original tree head")
	}
}

// TestRoleSeparationCommonAndGenericImplementationsAgree runs the common
// rfc6962.DefaultHasher (including its SHA-256 fast path) and an independent
// generic RFC 6962 implementation over the same legal logs, and cross-checks
// roots and proofs in both directions.
func TestRoleSeparationCommonAndGenericImplementationsAgree(t *testing.T) {
	common := rfc6962.DefaultHasher
	generic := rsGenericHasher{}

	if !bytes.Equal(common.EmptyRoot(), generic.EmptyRoot()) {
		t.Fatal("EmptyRoot implementations disagree")
	}
	probe := []byte("similar bytes across roles \x00\x01")
	if !bytes.Equal(common.HashLeaf(probe), generic.HashLeaf(probe)) {
		t.Error("HashLeaf implementations disagree")
	}
	x, y := common.HashLeaf([]byte("x")), common.HashLeaf([]byte("y"))
	if !bytes.Equal(common.HashChildren(x, y), generic.HashChildren(x, y)) {
		t.Error("HashChildren implementations disagree")
	}

	for n := 0; n <= 40; n++ {
		entries := rsEntries(n)

		commonTree := rsTree(t, common, entries)
		genericTree := testonly.New(generic)
		genericTree.AppendData(entries...)

		want := rsSpecRoot(entries)
		if got := commonTree.Hash(); !bytes.Equal(got, want) {
			t.Errorf("n=%d common Tree root %x != spec %x", n, got, want)
		}
		if got := genericTree.Hash(); !bytes.Equal(got, want) {
			t.Errorf("n=%d generic Tree root %x != spec %x", n, got, want)
		}
		if got := rsCompactRoot(t, common, entries); !bytes.Equal(got, want) {
			t.Errorf("n=%d compact(common) root mismatch", n)
		}
		if got := rsCompactRoot(t, generic, entries); !bytes.Equal(got, want) {
			t.Errorf("n=%d compact(generic) root mismatch", n)
		}

		for idx := uint64(0); idx < uint64(n); idx++ {
			// Proof built with the common hasher, verified by the generic one.
			pc, err := commonTree.InclusionProof(idx, uint64(n))
			if err != nil {
				t.Fatalf("n=%d idx=%d common proof: %v", n, idx, err)
			}
			if err := proof.VerifyInclusion(generic, idx, uint64(n), commonTree.LeafHash(idx), pc, commonTree.Hash()); err != nil {
				t.Errorf("n=%d idx=%d common proof not accepted by generic verifier: %v", n, idx, err)
			}
			// And the other way around.
			pg, err := genericTree.InclusionProof(idx, uint64(n))
			if err != nil {
				t.Fatalf("n=%d idx=%d generic proof: %v", n, idx, err)
			}
			if err := proof.VerifyInclusion(common, idx, uint64(n), genericTree.LeafHash(idx), pg, genericTree.Hash()); err != nil {
				t.Errorf("n=%d idx=%d generic proof not accepted by common verifier: %v", n, idx, err)
			}
		}
	}
}

// TestRoleSeparationInternalDigestAsLeafIsRejected is the core cross-layer
// attack: every interior digest of the honest tree is offered to the verifier
// as if it were a level-0 leaf hash, together with a correctly-sized inclusion
// proof, against the trusted tree head. None may validate.
func TestRoleSeparationInternalDigestAsLeafIsRejected(t *testing.T) {
	h := rfc6962.DefaultHasher
	const maxN = 16
	entries := rsEntries(maxN)

	for n := uint64(1); n <= maxN; n++ {
		tr := rsTree(t, h, entries[:n])
		trustedRoot := tr.Hash()
		internals := rsInternalNodes(t, h, entries, n)
		if len(internals) == 0 && n >= 2 {
			t.Fatalf("n=%d: expected interior nodes, harvested none", n)
		}

		for idx := uint64(0); idx < n; idx++ {
			honest, err := tr.InclusionProof(idx, n)
			if err != nil {
				t.Fatalf("n=%d idx=%d InclusionProof: %v", n, idx, err)
			}
			if err := proof.VerifyInclusion(h, idx, n, tr.LeafHash(idx), honest, trustedRoot); err != nil {
				t.Fatalf("n=%d idx=%d honest proof rejected: %v", n, idx, err)
			}

			for _, forgedLeaf := range internals {
				// The proof shape stays the honest, correctly-sized one; only the
				// claimed leaf hash is replaced by a higher-layer digest.
				err := proof.VerifyInclusion(h, idx, n, forgedLeaf, honest, trustedRoot)
				if err == nil {
					t.Errorf("n=%d idx=%d: interior node %x accepted as leaf against trusted root %x",
						n, idx, forgedLeaf, trustedRoot)
				}

				// The verifier still reconstructs *some* root from the forged
				// tuple (lengths are valid), but it must differ from the trusted
				// tree head.
				calcRoot, err := proof.RootFromInclusionProof(h, idx, n, forgedLeaf, honest)
				if err != nil {
					t.Errorf("n=%d idx=%d: RootFromInclusionProof on forged tuple failed: %v", n, idx, err)
					continue
				}
				if bytes.Equal(calcRoot, trustedRoot) {
					t.Errorf("n=%d idx=%d: forged cross-layer tuple reconstructs the trusted root", n, idx)
				}
			}
		}
	}
}

// TestRoleSeparationTreeHeadIsTheTrustBoundary demonstrates precisely where
// rejection comes from: a role-confused tuple is internally self-consistent
// under the root it calculates, so the security boundary is the externally
// trusted tree head. Against the honest head the internal-node-as-leaf claim
// fails; if an attacker could substitute the head too, verification would
// "pass" - which is why tree heads are what get signed/gossiped.
func TestRoleSeparationTreeHeadIsTheTrustBoundary(t *testing.T) {
	h := rfc6962.DefaultHasher
	entries := [][]byte{[]byte("e0"), []byte("e1"), []byte("e2"), []byte("e3")}
	tr := rsTree(t, h, entries)
	trustedHead := tr.Hash()

	// H(Leaf(e0), Leaf(e1)): a level-1 interior node.
	internal := tr.SubtreeHashAt(0, 2)
	honestProof0, err := tr.InclusionProof(0, 4)
	if err != nil {
		t.Fatal(err)
	}

	if err := proof.VerifyInclusion(h, 0, 4, tr.LeafHash(0), honestProof0, trustedHead); err != nil {
		t.Fatalf("honest proof: %v", err)
	}

	// Forge: present the interior node as the leaf at index 0.
	err = proof.VerifyInclusion(h, 0, 4, internal, honestProof0, trustedHead)
	if err == nil {
		t.Fatal("internal digest impersonating a leaf verified against the trusted tree head")
	}
	var mismatch proof.RootMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected RootMismatchError, got %T: %v", err, err)
	}
	if !bytes.Equal(mismatch.ExpectedRoot, trustedHead) {
		t.Error("mismatch error does not carry the trusted expected root")
	}

	forgedHead, err := proof.RootFromInclusionProof(h, 0, 4, internal, honestProof0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(forgedHead, trustedHead) {
		t.Fatal("forged tuple unexpectedly reconstructs the trusted head")
	}
	// The same tuple verifies only against its own calculated head.
	if err := proof.VerifyInclusion(h, 0, 4, internal, honestProof0, forgedHead); err != nil {
		t.Fatalf("tuple must be self-consistent under its calculated head: %v", err)
	}
}

// TestRoleSeparationCrossLayerProofComponents substitutes a single proof
// component with leaf or interior digests from the same log. The substituted
// proof verifies only when the replacement is byte-identical to the original
// component; every genuine cross-layer replacement is rejected.
func TestRoleSeparationCrossLayerProofComponents(t *testing.T) {
	h := rfc6962.DefaultHasher
	const maxN = 16
	entries := rsEntries(maxN)

	for n := uint64(2); n <= maxN; n++ {
		tr := rsTree(t, h, entries[:n])
		root := tr.Hash()

		candidates := make([][]byte, 0, 2*n)
		for i := uint64(0); i < n; i++ {
			candidates = append(candidates, tr.LeafHash(i))
		}
		candidates = append(candidates, rsInternalNodes(t, h, entries, n)...)

		for idx := uint64(0); idx < n; idx++ {
			honest, err := tr.InclusionProof(idx, n)
			if err != nil {
				t.Fatal(err)
			}
			leafHash := tr.LeafHash(idx)

			for pos := range honest {
				for _, cand := range candidates {
					forged := append([][]byte(nil), honest...)
					forged[pos] = cand
					err := proof.VerifyInclusion(h, idx, n, leafHash, forged, root)
					identical := bytes.Equal(cand, honest[pos])
					switch {
					case identical && err != nil:
						t.Errorf("n=%d idx=%d pos=%d: identical replacement rejected: %v", n, idx, pos, err)
					case !identical && err == nil:
						t.Errorf("n=%d idx=%d pos=%d: cross-layer/different component %x accepted",
							n, idx, pos, cand)
					}
				}
			}
		}
	}
}

// TestRoleSeparationNamedCrossLayerReplacements pins the two directional
// confusions with concrete small trees:
//   - an interior digest dropped into a leaf-sibling proof slot;
//   - a leaf digest dropped into an interior-sibling proof slot.
func TestRoleSeparationNamedCrossLayerReplacements(t *testing.T) {
	h := rfc6962.DefaultHasher
	entries := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tr := rsTree(t, h, entries)
	root := tr.Hash()

	la, lb, lc, ld := h.HashLeaf(entries[0]), h.HashLeaf(entries[1]), h.HashLeaf(entries[2]), h.HashLeaf(entries[3])
	pairAB := h.HashChildren(la, lb)
	pairCD := h.HashChildren(lc, ld)

	// Size 2, index 0: the sole proof component is the level-0 leaf hash lb.
	proof2 := [][]byte{lb}
	if err := proof.VerifyInclusion(h, 0, 2, la, proof2, h.HashChildren(la, lb)); err != nil {
		t.Fatalf("valid size-2 proof: %v", err)
	}
	if err := proof.VerifyInclusion(h, 0, 2, la, [][]byte{pairAB}, h.HashChildren(la, lb)); err == nil {
		t.Error("interior node placed in leaf-sibling slot was accepted")
	}

	// Size 4, index 0: proof is [lb, pairCD]; pairCD occupies an interior slot.
	proof4 := [][]byte{lb, pairCD}
	if err := proof.VerifyInclusion(h, 0, 4, la, proof4, root); err != nil {
		t.Fatalf("valid size-4 proof: %v", err)
	}
	if err := proof.VerifyInclusion(h, 0, 4, la, [][]byte{lb, lc}, root); err == nil {
		t.Error("leaf hash placed in interior-sibling slot was accepted")
	}
	if err := proof.VerifyInclusion(h, 0, 4, pairAB, proof4, root); err == nil {
		t.Error("interior pairAB used as the claimed leaf was accepted")
	}
	if err := proof.VerifyInclusion(h, 0, 4, pairAB, [][]byte{lb, pairCD}, root); err == nil {
		t.Error("interior digest as leaf with the untouched proof was accepted")
	}

	// ld is a leaf hash and must not be accepted where the interior pairCD is
	// required even though both are 32 bytes.
	if bytes.Equal(ld, pairCD) {
		t.Fatal("test setup collision: leaf digest equals interior digest")
	}
}

// TestRoleSeparationWrongOldHeadConsistency checks that feeding an interior
// digest as the trusted old tree head (size1) does not yield a valid
// consistency verification against the trusted new head.
func TestRoleSeparationWrongOldHeadConsistency(t *testing.T) {
	h := rfc6962.DefaultHasher
	const maxN = 8
	entries := rsEntries(maxN)
	tr := rsTree(t, h, entries)

	for n2 := uint64(2); n2 <= maxN; n2++ {
		newRoot := tr.HashAt(n2)
		internals := rsInternalNodes(t, h, entries, n2)
		for n1 := uint64(1); n1 < n2; n1++ {
			oldRoot := tr.HashAt(n1)
			cp, err := tr.ConsistencyProof(n1, n2)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d,%d): %v", n1, n2, err)
			}
			if err := proof.VerifyConsistency(h, n1, n2, cp, oldRoot, newRoot); err != nil {
				t.Fatalf("honest consistency %d->%d rejected: %v", n1, n2, err)
			}
			for _, fakeOld := range internals {
				if bytes.Equal(fakeOld, oldRoot) {
					continue // the genuine old head, not a substitution
				}
				if err := proof.VerifyConsistency(h, n1, n2, cp, fakeOld, newRoot); err == nil {
					t.Errorf("n1=%d n2=%d: interior/wrong digest %x accepted as old tree head", n1, n2, fakeOld)
				}
			}
		}
	}
}
