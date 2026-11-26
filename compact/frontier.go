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

package compact

// Frontier stores durable node hashes keyed by their stable NodeID. It is a
// convenient callback sink for witness-style consumers: ephemeral root nodes
// are ignored, while append-generated nodes are retained.
//
// The zero value is not initialized; use NewFrontier or make(Frontier).
type Frontier map[NodeID][]byte

// NewFrontier returns an initialized persistent-node store.
func NewFrontier() Frontier { return make(Frontier) }

// Visit stores persistent events and ignores ephemeral ones.
func (f Frontier) Visit(node Node) {
	if node.Source != SourcePersistent {
		return
	}
	f[node.ID] = append([]byte(nil), node.Hash...)
}

// VisitNode stores persistent events and ignores ephemeral ones.
func (f Frontier) VisitNode(node Node) { f.Visit(node) }

// OnNode is an alias for VisitNode.
func (f Frontier) OnNode(node Node) { f.Visit(node) }

// Event accepts a sourced event.
func (f Frontier) Event(node Node) { f.Visit(node) }

// VisitSource accepts the positional source-aware callback form.
func (f Frontier) VisitSource(id NodeID, hash []byte, source Source) {
	f.Visit(Node{ID: id, Hash: hash, Source: source})
}

// VisitPersistentNode implements SplitVisitor.
func (f Frontier) VisitPersistentNode(id NodeID, hash []byte) {
	f.Visit(Node{ID: id, Hash: hash, Source: SourcePersistent})
}

// VisitEphemeralNode implements SplitVisitor by discarding ephemeral nodes.
func (f Frontier) VisitEphemeralNode(NodeID, []byte) {}

// Add stores a persistent node.
func (f Frontier) Add(id NodeID, hash []byte) { f.VisitPersistentNode(id, hash) }

// Get returns the stored hash for id.
func (f Frontier) Get(id NodeID) []byte { return f[id] }

// Hashes returns stored hashes for the minimal nodes covering [begin, end).
func (f Frontier) Hashes(begin, end uint64) [][]byte {
	ids := RangeNodes(begin, end, nil)
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		hashes[i] = f[id]
	}
	return hashes
}

// Range reconstructs a compact range for [begin, end) from stored nodes.
func (f Frontier) Range(factory *RangeFactory, begin, end uint64) (*Range, error) {
	return factory.NewRange(begin, end, f.Hashes(begin, end))
}
