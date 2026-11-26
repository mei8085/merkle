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

// This file contains descriptively named aliases for the source-aware visitor
// entry points. The canonical methods are Append, AppendRange and
// GetRootHash, which accept both legacy and source-aware callback forms.

// AppendNode is an alias for Append.
func (r *Range) AppendNode(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendNodes is an alias for Append.
func (r *Range) AppendNodes(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithNode is an alias for Append.
func (r *Range) AppendWithNode(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithNodes is an alias for Append.
func (r *Range) AppendWithNodes(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithVisitor is an alias for Append.
func (r *Range) AppendWithVisitor(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithNodeVisitor is an alias for Append.
func (r *Range) AppendWithNodeVisitor(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithSource is an alias for Append.
func (r *Range) AppendWithSource(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithSourceVisitor is an alias for Append.
func (r *Range) AppendWithSourceVisitor(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendSource is an alias for Append.
func (r *Range) AppendSource(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendSourced is an alias for Append.
func (r *Range) AppendSourced(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendProvenance is an alias for Append.
func (r *Range) AppendProvenance(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendOrigin is an alias for Append.
func (r *Range) AppendOrigin(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendEvent is an alias for Append.
func (r *Range) AppendEvent(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithEvents is an alias for Append.
func (r *Range) AppendWithEvents(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendTracked is an alias for Append.
func (r *Range) AppendTracked(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendObserved is an alias for Append.
func (r *Range) AppendObserved(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendAndVisit is an alias for Append.
func (r *Range) AppendAndVisit(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendRangeNode is an alias for AppendRange.
func (r *Range) AppendRangeNode(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeNodes is an alias for AppendRange.
func (r *Range) AppendRangeNodes(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithNode is an alias for AppendRange.
func (r *Range) AppendRangeWithNode(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithNodes is an alias for AppendRange.
func (r *Range) AppendRangeWithNodes(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithVisitor is an alias for AppendRange.
func (r *Range) AppendRangeWithVisitor(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithNodeVisitor is an alias for AppendRange.
func (r *Range) AppendRangeWithNodeVisitor(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithSource is an alias for AppendRange.
func (r *Range) AppendRangeWithSource(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeSource is an alias for AppendRange.
func (r *Range) AppendRangeSource(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeEvent is an alias for AppendRange.
func (r *Range) AppendRangeEvent(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithEvents is an alias for AppendRange.
func (r *Range) AppendRangeWithEvents(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// RootHash is an alias for GetRootHash.
func (r *Range) RootHash(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashNode is an alias for GetRootHash.
func (r *Range) GetRootHashNode(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithNode is an alias for GetRootHash.
func (r *Range) GetRootHashWithNode(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithNodes is an alias for GetRootHash.
func (r *Range) GetRootHashWithNodes(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithVisitor is an alias for GetRootHash.
func (r *Range) GetRootHashWithVisitor(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithNodeVisitor is an alias for GetRootHash.
func (r *Range) GetRootHashWithNodeVisitor(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithSource is an alias for GetRootHash.
func (r *Range) GetRootHashWithSource(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashSource is an alias for GetRootHash.
func (r *Range) GetRootHashSource(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithEphemeral is an alias for GetRootHash.
func (r *Range) GetRootHashWithEphemeral(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashEphemeral is an alias for GetRootHash.
func (r *Range) GetRootHashEphemeral(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashDetailed is an alias for GetRootHash.
func (r *Range) GetRootHashDetailed(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashEvent is an alias for GetRootHash.
func (r *Range) GetRootHashEvent(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithEvents is an alias for GetRootHash.
func (r *Range) GetRootHashWithEvents(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashOrigin is an alias for GetRootHash.
func (r *Range) GetRootHashOrigin(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashProvenance is an alias for GetRootHash.
func (r *Range) GetRootHashProvenance(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// AppendWithNodeSource is an alias for Append.
func (r *Range) AppendWithNodeSource(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendNodeSource is an alias for Append.
func (r *Range) AppendNodeSource(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithOrigin is an alias for Append.
func (r *Range) AppendWithOrigin(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendWithProvenance is an alias for Append.
func (r *Range) AppendWithProvenance(hash []byte, visitor any) error {
	return r.Append(hash, visitor)
}

// AppendRangeWithNodeSource is an alias for AppendRange.
func (r *Range) AppendRangeWithNodeSource(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeNodeSource is an alias for AppendRange.
func (r *Range) AppendRangeNodeSource(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithOrigin is an alias for AppendRange.
func (r *Range) AppendRangeWithOrigin(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// AppendRangeWithProvenance is an alias for AppendRange.
func (r *Range) AppendRangeWithProvenance(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// GetRootHashWithNodeSource is an alias for GetRootHash.
func (r *Range) GetRootHashWithNodeSource(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashNodeSource is an alias for GetRootHash.
func (r *Range) GetRootHashNodeSource(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithOrigin is an alias for GetRootHash.
func (r *Range) GetRootHashWithOrigin(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// GetRootHashWithProvenance is an alias for GetRootHash.
func (r *Range) GetRootHashWithProvenance(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}

// AppendWithVisit is an alias for Append.
func (r *Range) AppendWithVisit(hash []byte, visitor any) error { return r.Append(hash, visitor) }

// AppendRangeWithVisit is an alias for AppendRange.
func (r *Range) AppendRangeWithVisit(other *Range, visitor any) error {
	return r.AppendRange(other, visitor)
}

// GetRootHashWithVisit is an alias for GetRootHash.
func (r *Range) GetRootHashWithVisit(visitor any) ([]byte, error) {
	return r.GetRootHash(visitor)
}
