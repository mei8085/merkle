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

package proof_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// newConsistencyTestTree returns a Merkle tree with |size| distinctly
// labelled leaves, using the RFC 6962 hasher.
func newConsistencyTestTree(t *testing.T, size uint64) *testonly.Tree {
	t.Helper()
	tree := testonly.New(rfc6962.DefaultHasher)
	for i := uint64(0); i < size; i++ {
		tree.AppendData([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return tree
}

// corruptHash returns a copy of the hash with one bit flipped, so that it
// commits to a different value.
func corruptHash(t *testing.T, h []byte) []byte {
	t.Helper()
	if len(h) == 0 {
		t.Fatal("cannot corrupt an empty hash")
	}
	c := bytes.Clone(h)
	c[0] ^= 0x01
	return c
}

// TestVerifyConsistencyBindsBothRoots checks that a consistency proof is only
// accepted when it commits to *both* the old and the new tree head: a proof
// that merely lets the new root be recomputed from some arbitrary old root
// must not validate a forged append-only history.
func TestVerifyConsistencyBindsBothRoots(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := newConsistencyTestTree(t, 8)

	// Cover perfect and non-perfect old trees, and proofs whose old-tree root
	// is itself a proof node vs. the chaining seed.
	for _, sizes := range [][2]uint64{{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 7}, {7, 8}, {3, 5}} {
		size1, size2 := sizes[0], sizes[1]
		t.Run(fmt.Sprintf("sizes_%d_%d", size1, size2), func(t *testing.T) {
			p, err := tree.ConsistencyProof(size1, size2)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", size1, size2, err)
			}
			root1 := tree.HashAt(size1)
			root2 := tree.HashAt(size2)

			t.Run("valid proof accepted", func(t *testing.T) {
				if err := proof.VerifyConsistency(hasher, size1, size2, p, root1, root2); err != nil {
					t.Fatalf("VerifyConsistency rejected a genuine append: %v", err)
				}
			})

			t.Run("forged old root rejected", func(t *testing.T) {
				fakeRoot1 := corruptHash(t, root1)
				// The forged old root still recomputes to *some* new root, but
				// it must not be accepted as the published one.
				if _, err := proof.RootFromConsistencyProof(hasher, size1, size2, p, fakeRoot1); err != nil {
					t.Logf("RootFromConsistencyProof with forged old root: %v", err)
				}
				if err := proof.VerifyConsistency(hasher, size1, size2, p, fakeRoot1, root2); err == nil {
					t.Fatal("VerifyConsistency accepted a forged old root")
				}
			})

			t.Run("old root from another tree size rejected", func(t *testing.T) {
				other := tree.HashAt(size2)
				if bytes.Equal(other, root1) {
					t.Skip("roots coincide for these sizes")
				}
				if err := proof.VerifyConsistency(hasher, size1, size2, p, other, root2); err == nil {
					t.Fatal("VerifyConsistency accepted an old root belonging to a different tree size")
				}
			})

			t.Run("forged new root rejected", func(t *testing.T) {
				if err := proof.VerifyConsistency(hasher, size1, size2, p, root1, corruptHash(t, root2)); err == nil {
					t.Fatal("VerifyConsistency accepted a forged new root")
				}
			})

			t.Run("swapped roots rejected", func(t *testing.T) {
				if bytes.Equal(root1, root2) {
					t.Skip("roots coincide for these sizes")
				}
				if err := proof.VerifyConsistency(hasher, size1, size2, p, root2, root1); err == nil {
					t.Fatal("VerifyConsistency accepted swapped roots")
				}
			})

			t.Run("tampered proof node rejected", func(t *testing.T) {
				if len(p) == 0 {
					t.Skip("empty proof")
				}
				tp := make([][]byte, len(p))
				for i, h := range p {
					tp[i] = bytes.Clone(h)
				}
				tp[len(tp)/2] = corruptHash(t, tp[len(tp)/2])
				if err := proof.VerifyConsistency(hasher, size1, size2, tp, root1, root2); err == nil {
					t.Fatal("VerifyConsistency accepted a tampered proof node")
				}
			})
		})
	}
}

// TestVerifyConsistencyForgedHistory checks that a consistency proof generated
// for one append-only history cannot be transplanted onto tree heads of a
// different history, even when the new root is reconstructible in isolation.
func TestVerifyConsistencyForgedHistory(t *testing.T) {
	hasher := rfc6962.DefaultHasher

	honest := newConsistencyTestTree(t, 8)
	// A forked history: same length, different leaf contents, so every root
	// commits to different data.
	forged := testonly.New(hasher)
	for i := uint64(0); i < 8; i++ {
		forged.AppendData([]byte(fmt.Sprintf("forged-leaf-%d", i)))
	}

	const size1, size2 = 3, 8
	honestProof, err := honest.ConsistencyProof(size1, size2)
	if err != nil {
		t.Fatalf("ConsistencyProof(%d, %d): %v", size1, size2, err)
	}
	forgedProof, err := forged.ConsistencyProof(size1, size2)
	if err != nil {
		t.Fatalf("forged ConsistencyProof(%d, %d): %v", size1, size2, err)
	}

	honestRoot1, honestRoot2 := honest.HashAt(size1), honest.HashAt(size2)
	forgedRoot1, forgedRoot2 := forged.HashAt(size1), forged.HashAt(size2)

	for _, tc := range []struct {
		desc         string
		proof        [][]byte
		root1, root2 []byte
	}{
		{"honest proof, forged old root", honestProof, forgedRoot1, honestRoot2},
		{"honest proof, forged new root", honestProof, honestRoot1, forgedRoot2},
		{"honest proof, both roots forged", honestProof, forgedRoot1, forgedRoot2},
		{"forged proof, honest roots", forgedProof, honestRoot1, honestRoot2},
		{"forged proof, forged old root, honest new root", forgedProof, forgedRoot1, honestRoot2},
		{"forged proof, honest old root, forged new root", forgedProof, honestRoot1, forgedRoot2},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if err := proof.VerifyConsistency(hasher, size1, size2, tc.proof, tc.root1, tc.root2); err == nil {
				t.Fatal("VerifyConsistency accepted a mismatched history")
			}
		})
	}

	// Sanity: each history is self-consistent and must verify on its own.
	if err := proof.VerifyConsistency(hasher, size1, size2, honestProof, honestRoot1, honestRoot2); err != nil {
		t.Fatalf("honest history rejected: %v", err)
	}
	if err := proof.VerifyConsistency(hasher, size1, size2, forgedProof, forgedRoot1, forgedRoot2); err != nil {
		t.Fatalf("self-consistent fork rejected: %v", err)
	}
}

// TestVerifyConsistencySameSizeHeads checks that tree heads of the same size
// obey the same trust boundary: the proof must be empty, and verification must
// bind the two roots to the same value rather than trusting either side.
func TestVerifyConsistencySameSizeHeads(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := newConsistencyTestTree(t, 8)

	for _, size := range []uint64{1, 3, 8} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			root := tree.HashAt(size)

			t.Run("identical roots accepted", func(t *testing.T) {
				if err := proof.VerifyConsistency(hasher, size, size, nil, root, root); err != nil {
					t.Fatalf("VerifyConsistency rejected identical same-size heads: %v", err)
				}
			})

			t.Run("different roots rejected", func(t *testing.T) {
				if err := proof.VerifyConsistency(hasher, size, size, nil, root, corruptHash(t, root)); err == nil {
					t.Fatal("VerifyConsistency accepted different roots for same-size heads")
				}
				if err := proof.VerifyConsistency(hasher, size, size, nil, corruptHash(t, root), root); err == nil {
					t.Fatal("VerifyConsistency accepted a forged old root for same-size heads")
				}
			})

			t.Run("roots from different sizes rejected", func(t *testing.T) {
				other := tree.HashAt(8)
				if size == 8 || bytes.Equal(other, root) {
					t.Skip("roots coincide")
				}
				if err := proof.VerifyConsistency(hasher, size, size, nil, root, other); err == nil {
					t.Fatal("VerifyConsistency accepted roots from different tree sizes for same-size heads")
				}
			})

			t.Run("non-empty proof rejected", func(t *testing.T) {
				bogus := [][]byte{root}
				if err := proof.VerifyConsistency(hasher, size, size, bogus, root, root); err == nil {
					t.Fatal("VerifyConsistency accepted a non-empty proof for same-size heads")
				}
			})
		})
	}
}

// TestVerifyConsistencyEmptyProof checks that an empty proof cannot make two
// tree heads with different root values share a trusted history: whenever the
// tree grew, a non-empty proof is required.
func TestVerifyConsistencyEmptyProof(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := newConsistencyTestTree(t, 8)

	for _, sizes := range [][2]uint64{{1, 2}, {3, 8}, {7, 8}} {
		size1, size2 := sizes[0], sizes[1]
		t.Run(fmt.Sprintf("sizes_%d_%d", size1, size2), func(t *testing.T) {
			root1, root2 := tree.HashAt(size1), tree.HashAt(size2)

			for _, p := range [][][]byte{nil, {}} {
				if err := proof.VerifyConsistency(hasher, size1, size2, p, root1, root2); err == nil {
					t.Error("VerifyConsistency accepted an empty proof for a grown tree")
				}
				// Even matching the new root on both sides must not help: the
				// old head of a smaller tree commits to a different value.
				if err := proof.VerifyConsistency(hasher, size1, size2, p, root2, root2); err == nil {
					t.Error("VerifyConsistency let an empty proof equate different-sized heads")
				}
			}

			if _, err := proof.RootFromConsistencyProof(hasher, size1, size2, nil, root1); err == nil {
				t.Error("RootFromConsistencyProof accepted an empty proof for a grown tree")
			}
		})
	}
}
