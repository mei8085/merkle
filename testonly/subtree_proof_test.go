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

package testonly

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/merkle/proof"
)

// TestSubtreeInclusionProofBindsToSubtreeCommitment checks that a member proof
// for a non-zero-start subtree restores exactly that subtree's commitment, and
// that a leaf from an adjacent range cannot be accepted by reusing the same
// proof or the same relative path.
func TestSubtreeInclusionProofBindsToSubtreeCommitment(t *testing.T) {
	const size = uint64(64)
	mt := newTree(genEntries(size))
	h := mt.hasher

	for end := uint64(2); end <= size; end++ {
		for start := range end {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			want := mt.SubtreeHashAt(start, end)
			for index := start; index < end; index++ {
				p, err := mt.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				if err := proof.VerifySubtreeInclusion(h, index, start, end, mt.LeafHash(index), p, want); err != nil {
					t.Fatalf("VerifySubtreeInclusion(%d, %d, %d): %v", index, start, end, err)
				}

				// A leaf immediately outside the subtree must not be provable as a
				// member of it, even using this subtree's proof path.
				var adjacent uint64
				switch {
				case start > 0:
					adjacent = start - 1
				case end < size:
					adjacent = end
				}
				if start > 0 || end < size {
					if err := proof.VerifySubtreeInclusion(h, index, start, end, mt.LeafHash(adjacent), p, want); err == nil {
						t.Errorf("SubtreeInclusionProof(%d, %d, %d): adjacent leaf %d accepted", index, start, end, adjacent)
					}
				}

				// A same-shaped adjacent subtree, if it exists, has a leaf at the same
				// relative offset. Its leaf hash must not verify through this subtree's
				// proof, neither against this subtree's root nor against its own.
				// A singleton subtree has an empty proof, so there is no borrowed node
				// to replay; only the cross-commitment check below is meaningful there.
				length := end - start
				if length&(length-1) != 0 { // Only perfect subtrees tile the log.
					continue
				}
				var otherStart uint64
				switch {
				case start+2*length <= size:
					otherStart = start + length
				case start >= length:
					otherStart = start - length
				default:
					continue
				}
				otherEnd := otherStart + length
				otherIndex := otherStart + (index - start)
				otherRoot := mt.SubtreeHashAt(otherStart, otherEnd)
				if length > 1 {
					if err := proof.VerifySubtreeInclusion(h, otherIndex, otherStart, otherEnd, mt.LeafHash(otherIndex), p, otherRoot); err == nil {
						t.Errorf("SubtreeInclusionProof(%d, %d, %d): proof accepted for adjacent subtree [%d, %d) via the same relative path", index, start, end, otherStart, otherEnd)
					}
				}
				if err := proof.VerifySubtreeInclusion(h, otherIndex, otherStart, otherEnd, mt.LeafHash(otherIndex), p, want); err == nil {
					t.Errorf("SubtreeInclusionProof(%d, %d, %d): adjacent leaf accepted against target commitment", index, start, end)
				}
				otherProof, err := mt.SubtreeInclusionProof(otherIndex, otherStart, otherEnd)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", otherIndex, otherStart, otherEnd, err)
				}
				if err := proof.VerifySubtreeInclusion(h, otherIndex, otherStart, otherEnd, mt.LeafHash(otherIndex), otherProof, want); err == nil {
					t.Errorf("SubtreeInclusionProof(%d, %d, %d): proof of adjacent subtree accepted against target commitment", otherIndex, otherStart, otherEnd)
				}
			}
		}
	}
}

// TestSubtreeInclusionProofRejectsWrongIndex checks that a member proof is
// bound to the exact leaf it was produced for: a wrong index is never accepted
// as membership of another leaf, whether the leaf hash is swapped or not.
func TestSubtreeInclusionProofRejectsWrongIndex(t *testing.T) {
	const size = uint64(64)
	mt := newTree(genEntries(size))
	h := mt.hasher

	for end := uint64(2); end <= size; end++ {
		for start := range end {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			want := mt.SubtreeHashAt(start, end)
			for index := start; index < end; index++ {
				p, err := mt.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				// Try every other leaf in the subtree as a candidate for membership.
				for wrong := start; wrong < end; wrong++ {
					if wrong == index {
						continue
					}
					if err := proof.VerifySubtreeInclusion(h, wrong, start, end, mt.LeafHash(wrong), p, want); err == nil {
						t.Errorf("SubtreeInclusionProof(%d, %d, %d): accepted as membership of leaf %d", index, start, end, wrong)
					}
					if err := proof.VerifySubtreeInclusion(h, wrong, start, end, mt.LeafHash(index), p, want); err == nil {
						t.Errorf("SubtreeInclusionProof(%d, %d, %d): leaf accepted at wrong index %d", index, start, end, wrong)
					}
				}
			}
		}
	}
}

// TestSubtreeInclusionProofNodesAreGlobal checks that the node IDs in a
// non-zero-start subtree proof are global storage coordinates:
//   - every ID is fetchable from the global node storage;
//   - its coverage lies inside the target subtree;
//   - its level matches the equivalent zero-start proof (only indices shift);
//   - rehashing the fetched nodes restores the target subtree commitment.
//
// It also checks that the unshifted relative IDs cannot restore the commitment,
// which is what binds the proof nodes to the shifted subtree head.
func TestSubtreeInclusionProofNodesAreGlobal(t *testing.T) {
	const size = uint64(64)
	mt := newTree(genEntries(size))
	h := mt.hasher

	for end := uint64(2); end <= size; end++ {
		for start := range end {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			length := end - start
			want := mt.SubtreeHashAt(start, end)
			for index := start; index < end; index++ {
				nodes, err := proof.SubtreeInclusion(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusion(%d, %d, %d): %v", index, start, end, err)
				}
				rel, err := proof.SubtreeInclusion(index-start, 0, length)
				if err != nil {
					t.Fatalf("SubtreeInclusion(%d, 0, %d): %v", index-start, length, err)
				}
				if len(nodes.IDs) != len(rel.IDs) {
					t.Fatalf("SubtreeInclusion(%d, %d, %d): %d nodes, want %d", index, start, end, len(nodes.IDs), len(rel.IDs))
				}

				global := make([][]byte, len(nodes.IDs))
				for i, id := range nodes.IDs {
					lo, hi := id.Coverage()
					if lo < start || hi > end {
						t.Errorf("SubtreeInclusion(%d, %d, %d): node %v covers [%d, %d) outside the subtree", index, start, end, id, lo, hi)
					}
					if id.Level != rel.IDs[i].Level {
						t.Errorf("SubtreeInclusion(%d, %d, %d): node %d level=%d, want %d", index, start, end, i, id.Level, rel.IDs[i].Level)
					}
					if wantIdx := rel.IDs[i].Index + (start >> id.Level); id.Index != wantIdx {
						t.Errorf("SubtreeInclusion(%d, %d, %d): node %d=%v, want global index %d", index, start, end, i, id, wantIdx)
					}
					if id.Level >= uint(len(mt.hashes)) || id.Index >= uint64(len(mt.hashes[id.Level])) {
						t.Fatalf("SubtreeInclusion(%d, %d, %d): node %v missing from global storage", index, start, end, id)
					}
					global[i] = mt.hashes[id.Level][id.Index]
				}
				rehashed, err := nodes.Rehash(global, h.HashChildren)
				if err != nil {
					t.Fatalf("Rehash: %v", err)
				}
				root, err := proof.RootFromInclusionProof(h, index-start, length, mt.LeafHash(index), rehashed)
				if err != nil {
					t.Fatalf("RootFromInclusionProof: %v", err)
				}
				if !bytes.Equal(root, want) {
					t.Errorf("SubtreeInclusion(%d, %d, %d): global nodes rehash to %x, want %x", index, start, end, root, want)
				}

				// The unshifted relative node IDs point into a different part of the
				// log. Fetching those must not restore the shifted subtree commitment.
				// A singleton proof has no nodes at all, so there is nothing to compare.
				if start < length || len(rel.IDs) == 0 {
					continue // Relative and shifted ranges overlap, or no nodes at all.
				}
				relative := make([][]byte, len(rel.IDs))
				for i, id := range rel.IDs {
					if id.Level >= uint(len(mt.hashes)) || id.Index >= uint64(len(mt.hashes[id.Level])) {
						t.Fatalf("SubtreeInclusion(%d, 0, %d): node %v missing from global storage", index-start, length, id)
					}
					relative[i] = mt.hashes[id.Level][id.Index]
				}
				rehashedRel, err := rel.Rehash(relative, h.HashChildren)
				if err != nil {
					t.Fatalf("Rehash: %v", err)
				}
				if root, err := proof.RootFromInclusionProof(h, index-start, length, mt.LeafHash(index), rehashedRel); err != nil {
					t.Fatalf("RootFromInclusionProof: %v", err)
				} else if bytes.Equal(root, want) {
					t.Errorf("SubtreeInclusion(%d, %d, %d): unshifted relative nodes [%v] restored the shifted commitment", index, start, end, rel.IDs)
				}
				if err := proof.VerifySubtreeInclusion(h, index, start, end, mt.LeafHash(index), mustRehash(t, rel, relative, h.HashChildren), want); err == nil {
					t.Errorf("SubtreeInclusion(%d, %d, %d): unshifted relative proof accepted against shifted commitment", index, start, end)
				}
			}
		}
	}
}

// mustRehash rehashes a copy of hashes using the node layout, and fails the
// test on error.
func mustRehash(t *testing.T, nodes proof.Nodes, hashes [][]byte, hc func(left, right []byte) []byte) [][]byte {
	t.Helper()
	cp := make([][]byte, len(hashes))
	for i := range hashes {
		cp[i] = append([]byte(nil), hashes[i]...)
	}
	got, err := nodes.Rehash(cp, hc)
	if err != nil {
		t.Fatalf("Rehash: %v", err)
	}
	return got
}

// TestSubtreeInclusionProofZeroStartUnchanged checks that a zero-start subtree
// keeps the original inclusion contract: its proof and node positions are
// identical to Inclusion, so existing callers and proofs remain valid.
func TestSubtreeInclusionProofZeroStartUnchanged(t *testing.T) {
	const size = uint64(64)
	mt := newTree(genEntries(size))
	h := mt.hasher

	for end := uint64(1); end <= size; end++ {
		for index := range end {
			got, err := proof.SubtreeInclusion(index, 0, end)
			if err != nil {
				t.Fatalf("SubtreeInclusion(%d, 0, %d): %v", index, end, err)
			}
			want, err := proof.Inclusion(index, end)
			if err != nil {
				t.Fatalf("Inclusion(%d, %d): %v", index, end, err)
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(proof.Nodes{})); diff != "" {
				t.Fatalf("SubtreeInclusion(%d, 0, %d) != Inclusion: diff (-want +got)\n%s", index, end, diff)
			}

			gotProof, err := mt.SubtreeInclusionProof(index, 0, end)
			if err != nil {
				t.Fatalf("SubtreeInclusionProof(%d, 0, %d): %v", index, end, err)
			}
			wantProof, err := mt.InclusionProof(index, end)
			if err != nil {
				t.Fatalf("InclusionProof(%d, %d): %v", index, end, err)
			}
			if len(gotProof) != len(wantProof) {
				t.Fatalf("SubtreeInclusionProof(%d, 0, %d): %d hashes, want %d", index, end, len(gotProof), len(wantProof))
			}
			for i := range wantProof {
				if !bytes.Equal(gotProof[i], wantProof[i]) {
					t.Fatalf("SubtreeInclusionProof(%d, 0, %d): hash %d mismatch", index, end, i)
				}
			}
			if err := proof.VerifyInclusion(h, index, end, mt.LeafHash(index), gotProof, mt.HashAt(end)); err != nil {
				t.Fatalf("VerifyInclusion(%d, %d): %v", index, end, err)
			}
		}
	}
}
