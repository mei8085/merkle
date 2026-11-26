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

package compact_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/merkle/compact"
)

// stageCommitment is a published tree head: the compact-range frontier and the
// root hash committing to the leaf sequence [0, size).
type stageCommitment struct {
	size     uint64
	frontier [][]byte
	root     []byte
}

// staticFrontier naively computes the compact-range frontier of [begin, end)
// directly from a statically built Merkle tree, independently of the
// incremental compact.Range merging machinery.
func staticFrontier(tr *tree, begin, end uint64) [][]byte {
	left, right := compact.Decompose(begin, end)
	pos := begin
	var hashes [][]byte
	for lvl := uint(0); lvl < 64; lvl++ {
		if left&(1<<lvl) != 0 {
			hashes = append(hashes, tr.nodes[lvl][pos>>lvl].hash)
			pos += 1 << lvl
		}
	}
	for lvl := uint(63); lvl < 64; lvl-- { // Overflows on the last iteration.
		if right&(1<<lvl) != 0 {
			hashes = append(hashes, tr.nodes[lvl][pos>>lvl].hash)
			pos += 1 << lvl
		}
	}
	return hashes
}

// referenceCommitment computes the commitment to the leaf sequence [0, size)
// from a statically built tree, serving as the independent ground truth that
// all merging strategies are compared against.
func referenceCommitment(t *testing.T, size uint64) stageCommitment {
	t.Helper()
	tr, _ := newTree(t, size)
	return stageCommitment{size: size, frontier: staticFrontier(tr, 0, size), root: tr.rootHash()}
}

// checkCommitment verifies that the range state matches the reference
// commitment: same end position, same frontier nodes, same root hash.
func checkCommitment(t *testing.T, cr *compact.Range, ref stageCommitment) {
	t.Helper()
	if got := cr.End(); got != ref.size {
		t.Fatalf("range end = %d, want %d", got, ref.size)
	}
	if diff := cmp.Diff(cr.Hashes(), ref.frontier); diff != "" {
		t.Errorf("frontier mismatch at size %d (-got +want):\n%s", ref.size, diff)
	}
	root, err := cr.GetRootHash(nil)
	if err != nil {
		t.Fatalf("GetRootHash at size %d: %v", ref.size, err)
	}
	if !bytes.Equal(root, ref.root) {
		t.Errorf("root hash mismatch at size %d: got %x, want %x", ref.size, shorten(root), shorten(ref.root))
	}
}

// leafRecorder records the leaf nodes reported through a visitor, to verify
// that a merging strategy commits to every leaf exactly once, at its canonical
// position in the leaf sequence.
type leafRecorder struct {
	t      *testing.T
	leaves map[uint64][]byte
}

func (r *leafRecorder) visit(id compact.NodeID, hash []byte) {
	if id.Level != 0 {
		return
	}
	if r.leaves == nil {
		r.leaves = make(map[uint64][]byte)
	}
	if _, ok := r.leaves[id.Index]; ok {
		r.t.Errorf("leaf %d committed more than once", id.Index)
		return
	}
	r.leaves[id.Index] = slices.Clone(hash)
}

// check verifies that exactly the leaves [0, n) were committed to, each with
// the hash matching the statically built tree.
func (r *leafRecorder) check(t *testing.T, tr *tree, n uint64) {
	t.Helper()
	if got, want := len(r.leaves), int(n); got != want {
		t.Errorf("committed %d distinct leaves, want %d", got, want)
	}
	for i := uint64(0); i < n; i++ {
		hash, ok := r.leaves[i]
		if !ok {
			t.Errorf("leaf %d was never committed", i)
			continue
		}
		if want := tr.leaf(i); !bytes.Equal(hash, want) {
			t.Errorf("leaf %d hash = %x, want %x", i, shorten(hash), shorten(want))
		}
	}
}

// TestWitnessStageCommitmentsEquivalence simulates a transparency log witness
// that receives adjacent leaf ranges in batches and publishes a tree head at
// each stage boundary. It verifies that, regardless of how the leaf sequence
// is split into batches or in which direction ranges are merged, every
// strategy arrives at the same leaf positions, frontier nodes, and stage
// roots — independent commitments to the one and the same leaf sequence.
func TestWitnessStageCommitmentsEquivalence(t *testing.T) {
	const numLeaves = uint64(100)
	// Unevenly spaced stage boundaries at which tree heads get published.
	stages := []uint64{0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 100}

	full, fullVisit := newTree(t, numLeaves)

	// Reference commitments computed directly from statically built trees.
	ref := make(map[uint64]stageCommitment, len(stages))
	for _, size := range stages {
		ref[size] = referenceCommitment(t, size)
	}

	// runStrategy runs a forward merging strategy, checking the commitment
	// against the reference whenever the frontier reaches a stage boundary.
	runStrategy := func(t *testing.T, extend func(cr *compact.Range, visit compact.VisitFn, checkpoint func())) {
		rec := &leafRecorder{t: t}
		visit := func(id compact.NodeID, hash []byte) {
			fullVisit(id, hash) // Validates the hash against the static tree node.
			rec.visit(id, hash)
		}
		cr := factory.NewEmptyRange(0)
		next := 0
		checkpoint := func() {
			for next < len(stages) && stages[next] == cr.End() {
				checkCommitment(t, cr, ref[stages[next]])
				next++
			}
		}
		checkpoint()
		extend(cr, visit, checkpoint)
		if next != len(stages) {
			t.Errorf("missed %d stage boundaries, last reached size %d", len(stages)-next, cr.End())
		}
		rec.check(t, full, numLeaves)
	}

	// Leaf-by-leaf append: the finest possible batching.
	t.Run("leaves", func(t *testing.T) {
		runStrategy(t, func(cr *compact.Range, visit compact.VisitFn, checkpoint func()) {
			for i := uint64(0); i < numLeaves; i++ {
				if err := cr.Append(full.leaf(i), visit); err != nil {
					t.Fatalf("Append(%d): %v", i, err)
				}
				checkpoint()
			}
		})
	})

	// Batches of bounded size, clipped at stage boundaries so that the
	// published heads are reachable. Different batch sizes exercise different
	// merge paths through the same leaf sequence.
	for _, batchSize := range []uint64{7, 16, 1000} {
		t.Run(fmt.Sprintf("batches:%d", batchSize), func(t *testing.T) {
			runStrategy(t, func(cr *compact.Range, visit compact.VisitFn, checkpoint func()) {
				for begin := uint64(0); begin < numLeaves; {
					end := begin + batchSize
					// Clip the batch at the next unpublished stage boundary.
					for _, s := range stages {
						if s > begin && s < end {
							end = s
						}
					}
					if end > numLeaves {
						end = numLeaves
					}
					batch := factory.NewEmptyRange(begin)
					for i := begin; i < end; i++ {
						if err := batch.Append(full.leaf(i), visit); err != nil {
							t.Fatalf("Append(%d): %v", i, err)
						}
					}
					if err := cr.AppendRange(batch, visit); err != nil {
						t.Fatalf("AppendRange([%d,%d)): %v", begin, end, err)
					}
					checkpoint()
					begin = end
				}
			})
		})
	}

	// Backwards merging: the tree is assembled right-to-left by prepending
	// stage-sized batches. Intermediate states are suffix ranges; every stage
	// split of the leaf sequence must still recombine into the same final
	// commitment.
	t.Run("backwards", func(t *testing.T) {
		rec := &leafRecorder{t: t}
		visit := func(id compact.NodeID, hash []byte) {
			fullVisit(id, hash)
			rec.visit(id, hash)
		}

		suffixes := make(map[uint64]*compact.Range, len(stages))
		total := factory.NewEmptyRange(numLeaves)
		suffixes[numLeaves] = total
		for s := len(stages) - 1; s > 0; s-- {
			begin, end := stages[s-1], stages[s]
			batch := factory.NewEmptyRange(begin)
			for i := begin; i < end; i++ {
				if err := batch.Append(full.leaf(i), visit); err != nil {
					t.Fatalf("Append(%d): %v", i, err)
				}
			}
			if err := batch.AppendRange(total, visit); err != nil {
				t.Fatalf("AppendRange([%d,%d)): %v", begin, end, err)
			}
			total = batch
			suffixes[begin] = total
			// The suffix frontier matches the statically built tree.
			full.verifyRange(t, total, true)
		}

		// The final frontier and root equal the reference commitment.
		if diff := cmp.Diff(total.Hashes(), ref[numLeaves].frontier); diff != "" {
			t.Errorf("final frontier mismatch (-got +want):\n%s", diff)
		}
		root, err := total.GetRootHash(nil)
		if err != nil {
			t.Fatalf("GetRootHash: %v", err)
		}
		if !bytes.Equal(root, ref[numLeaves].root) {
			t.Errorf("final root = %x, want %x", shorten(root), shorten(ref[numLeaves].root))
		}
		rec.check(t, full, numLeaves)

		// Merging the forward-built prefix [0, s) with the backwards-built
		// suffix [s, N) reproduces the same final commitment at every stage
		// boundary s: the two merge directions commit to the same leaves.
		for _, s := range stages[1 : len(stages)-1] {
			prefix := factory.NewEmptyRange(0)
			for i := uint64(0); i < s; i++ {
				if err := prefix.Append(full.leaf(i), nil); err != nil {
					t.Fatalf("Append(%d): %v", i, err)
				}
			}
			if err := prefix.AppendRange(suffixes[s], nil); err != nil {
				t.Fatalf("AppendRange at stage %d: %v", s, err)
			}
			checkCommitment(t, prefix, ref[numLeaves])
		}
	})
}

// TestWitnessRejectsNonContiguousHistory verifies that inputs which cannot
// form a continuous append history are rejected without disturbing the
// witness: the published tree head and the in-memory frontier stay intact,
// and a subsequent legal append continues from the original commitment.
func TestWitnessRejectsNonContiguousHistory(t *testing.T) {
	const numLeaves = uint64(34)
	const published = uint64(13)
	full, fullVisit := newTree(t, numLeaves)

	buildRange := func(begin, end uint64) *compact.Range {
		t.Helper()
		r := factory.NewEmptyRange(begin)
		for i := begin; i < end; i++ {
			if err := r.Append(full.leaf(i), fullVisit); err != nil {
				t.Fatalf("Append(%d): %v", i, err)
			}
		}
		return r
	}

	// The witness accumulates the leaf sequence in uneven batches and
	// publishes the tree head at size 13.
	witness := factory.NewEmptyRange(0)
	for _, iv := range [][2]uint64{{0, 4}, {4, 9}, {9, published}} {
		if err := witness.AppendRange(buildRange(iv[0], iv[1]), fullVisit); err != nil {
			t.Fatalf("AppendRange([%d,%d)): %v", iv[0], iv[1], err)
		}
	}
	publishedRoot, err := witness.GetRootHash(nil)
	if err != nil {
		t.Fatalf("GetRootHash: %v", err)
	}
	if want := referenceCommitment(t, published); !bytes.Equal(publishedRoot, want.root) {
		t.Fatalf("published root = %x, want %x", shorten(publishedRoot), shorten(want.root))
	}
	// Deep-clone the frontier so that later in-place mutations can't alias it.
	frontier := make([][]byte, len(witness.Hashes()))
	for i, h := range witness.Hashes() {
		frontier[i] = slices.Clone(h)
	}

	// checkIntact verifies that the published head and the in-memory frontier
	// are exactly as they were right after publishing.
	checkIntact := func() {
		t.Helper()
		if got := witness.End(); got != published {
			t.Errorf("witness end = %d, want %d", got, published)
		}
		if diff := cmp.Diff(witness.Hashes(), frontier); diff != "" {
			t.Errorf("frontier mutated after rejected input (-got +want):\n%s", diff)
		}
		root, err := witness.GetRootHash(nil)
		if err != nil {
			t.Errorf("GetRootHash: %v", err)
		} else if !bytes.Equal(root, publishedRoot) {
			t.Errorf("root = %x, want published %x", shorten(root), shorten(publishedRoot))
		}
	}

	// Malformed inputs are rejected at construction, before reaching the
	// witness.
	if _, err := factory.NewRange(published, 20, nil); err == nil {
		t.Error("NewRange with too few hashes succeeded unexpectedly")
	}
	if _, err := factory.NewRange(20, published, nil); err == nil {
		t.Error("NewRange with end < begin succeeded unexpectedly")
	}
	checkIntact()

	// Inputs that cannot extend the published history are rejected.
	for _, tc := range []struct {
		desc       string
		begin, end uint64
		inTree     bool // Whether the range leaves exist in the static tree.
	}{
		{desc: "gap", begin: 14, end: 20, inTree: true},         // Skips leaf 13.
		{desc: "overlap", begin: 10, end: 20, inTree: true},     // Re-commits leaves 10-12.
		{desc: "replay", begin: 0, end: 5, inTree: true},        // Replays old history.
		{desc: "future", begin: 1000, end: 1010, inTree: false}, // Far beyond the frontier.
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var batch *compact.Range
			if tc.inTree {
				batch = buildRange(tc.begin, tc.end)
			} else {
				// The leaves are beyond the static tree; hash them locally.
				batch = factory.NewEmptyRange(tc.begin)
				for i := tc.begin; i < tc.end; i++ {
					if err := batch.Append(hashLeaf(leafData(i)), nil); err != nil {
						t.Fatalf("Append(%d): %v", i, err)
					}
				}
			}
			if err := witness.AppendRange(batch, nil); err == nil {
				t.Errorf("AppendRange([%d,%d)) succeeded unexpectedly", tc.begin, tc.end)
			}
			checkIntact()
			// The rejected input itself is not consumed and stays valid.
			if tc.inTree {
				full.verifyRange(t, batch, true)
			}
		})
	}

	// A range built by a different factory is incompatible.
	t.Run("foreign_factory", func(t *testing.T) {
		alt := &compact.RangeFactory{Hash: factory.Hash}
		other := alt.NewEmptyRange(published)
		for i := published; i < 20; i++ {
			if err := other.Append(full.leaf(i), nil); err != nil {
				t.Fatalf("Append(%d): %v", i, err)
			}
		}
		if err := witness.AppendRange(other, nil); err == nil {
			t.Error("AppendRange with foreign factory succeeded unexpectedly")
		}
		checkIntact()
	})

	// Merging an empty adjacent range is a legal no-op.
	if err := witness.AppendRange(factory.NewEmptyRange(published), nil); err != nil {
		t.Errorf("AppendRange(empty): %v", err)
	}
	checkIntact()

	// A legal append continues from the original commitment: the next batch
	// extends the published head, and the new commitment matches the one
	// computed independently from the same leaf sequence.
	if err := witness.AppendRange(buildRange(published, 21), fullVisit); err != nil {
		t.Fatalf("AppendRange([%d,%d)): %v", published, 21, err)
	}
	checkCommitment(t, witness, referenceCommitment(t, 21))

	// Leaf-by-leaf appends keep extending the same history to the final head.
	for i := uint64(21); i < numLeaves; i++ {
		if err := witness.Append(full.leaf(i), fullVisit); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	checkCommitment(t, witness, referenceCommitment(t, numLeaves))
}
