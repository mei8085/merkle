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

import (
	"fmt"
	"reflect"
	"strings"
)

// Source describes why a node is reported to a visitor.
//
// The zero value is SourcePersistent: nodes produced while appending entries
// are immutable perfect nodes and may be retained as the log's frontier.
type Source int

const (
	SourceUnknown Source = -1

	// SourcePersistent identifies a node that belongs to the append-only node
	// history. Such a node has a stable NodeID and hash, and can be stored and
	// reused when appending more leaves.
	SourcePersistent Source = 0
	// SourceEphemeral identifies a temporary node synthesized only while
	// computing an imperfect tree root. The same NodeID can later denote a
	// different persistent node, so consumers must not use these events as
	// durable frontier state.
	SourceEphemeral Source = 1
)

// NodeSource is an alias for Source, kept under the explicit name used by
// source-aware visitors.
type NodeSource = Source

// NodeOrigin and the aliases below accommodate the terminology used by callers
// that distinguish node provenance rather than source.
type NodeOrigin = Source

// Origin is an alias for Source.
type Origin = Source

// Provenance is an alias for Source.
type Provenance = Source

// NodeProvenance is an alias for Source.
type NodeProvenance = Source

// Kind and NodeKind are aliases for Source.
type Kind = Source
type NodeKind = Source

// Type and NodeType are aliases for Source.
type Type = Source
type NodeType = Source

// Source value aliases with common naming prefixes.
const (
	Persistent = SourcePersistent
	Ephemeral  = SourceEphemeral

	NodePersistent   = SourcePersistent
	NodeEphemeral    = SourceEphemeral
	PersistentNode   = SourcePersistent
	EphemeralNode    = SourceEphemeral
	PersistentSource = SourcePersistent
	EphemeralSource  = SourceEphemeral

	NodeSourcePersistent  = SourcePersistent
	NodeSourceEphemeral   = SourceEphemeral
	NodeSourceUnknown     = SourceUnknown
	NodeSourceUnspecified = SourceUnknown
	SourceUnspecified     = SourceUnknown
	Unspecified           = SourceUnknown
	Unknown               = SourceUnknown

	OriginPersistent         = SourcePersistent
	OriginEphemeral          = SourceEphemeral
	PersistentOrigin         = SourcePersistent
	EphemeralOrigin          = SourceEphemeral
	NodeOriginPersistent     = SourcePersistent
	NodeOriginEphemeral      = SourceEphemeral
	ProvenancePersistent     = SourcePersistent
	ProvenanceEphemeral      = SourceEphemeral
	NodeProvenancePersistent = SourcePersistent
	NodeProvenanceEphemeral  = SourceEphemeral

	KindPersistent     = SourcePersistent
	KindEphemeral      = SourceEphemeral
	NodeKindPersistent = SourcePersistent
	NodeKindEphemeral  = SourceEphemeral
	TypePersistent     = SourcePersistent
	TypeEphemeral      = SourceEphemeral
	NodeTypePersistent = SourcePersistent
	NodeTypeEphemeral  = SourceEphemeral

	// Call-site-oriented names. Append, merge and leaf events are persistent;
	// root-hash events are ephemeral.
	SourceAppend      = SourcePersistent
	SourceAppendRange = SourcePersistent
	SourceLeaf        = SourcePersistent
	SourceMerge       = SourcePersistent
	SourceNew         = SourcePersistent
	SourceCreated     = SourcePersistent
	SourceCommitted   = SourcePersistent
	SourceCanonical   = SourcePersistent
	SourceReal        = SourcePersistent
	SourceDurable     = SourcePersistent

	SourceRoot      = SourceEphemeral
	SourceRootHash  = SourceEphemeral
	SourceTemporary = SourceEphemeral
	SourceTransient = SourceEphemeral
	SourceComputed  = SourceEphemeral
	SourceSynthetic = SourceEphemeral

	NodeSourceAppend      = SourcePersistent
	NodeSourceAppendRange = SourcePersistent
	NodeSourceLeaf        = SourcePersistent
	NodeSourceMerge       = SourcePersistent
	NodeSourceNew         = SourcePersistent
	NodeSourceCreated     = SourcePersistent
	NodeSourceCommitted   = SourcePersistent
	NodeSourceCanonical   = SourcePersistent
	NodeSourceReal        = SourcePersistent
	NodeSourceDurable     = SourcePersistent
	NodeSourceTemporary   = SourceEphemeral
	NodeSourceTransient   = SourceEphemeral
	NodeSourceComputed    = SourceEphemeral
	NodeSourceSynthetic   = SourceEphemeral
	NodeSourceRoot        = SourceEphemeral
	NodeSourceRootHash    = SourceEphemeral
)

// Additional adjective aliases.
const (
	Real      = SourcePersistent
	Committed = SourcePersistent
	Canonical = SourcePersistent
	Durable   = SourcePersistent
	Temporary = SourceEphemeral
	Transient = SourceEphemeral
	Computed  = SourceEphemeral
	Synthetic = SourceEphemeral
)

// String returns a stable human-readable source name.
func (s Source) String() string {
	switch s {
	case SourceUnknown:
		return "unknown"
	case SourcePersistent:
		return "persistent"
	case SourceEphemeral:
		return "ephemeral"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// Persistent reports whether s denotes a durable node source.
func (s Source) Persistent() bool { return s == SourcePersistent }

// IsPersistent reports whether s denotes a durable node source.
func (s Source) IsPersistent() bool { return s == SourcePersistent }

// Ephemeral reports whether s denotes a temporary root-computation node.
func (s Source) Ephemeral() bool { return s == SourceEphemeral }

// IsEphemeral reports whether s denotes a temporary root-computation node.
func (s Source) IsEphemeral() bool { return s == SourceEphemeral }

// Node is a node event together with its source.
type Node struct {
	// ID is the node coordinate in the standard Merkle address space.
	ID NodeID
	// Hash is the node hash.
	Hash []byte
	// Source distinguishes durable append nodes from ephemeral root nodes.
	Source Source
}

// NewNode returns a sourced node event.
func NewNode(id NodeID, hash []byte, source Source) Node {
	return Node{ID: id, Hash: hash, Source: source}
}

// NewSourcedNode is an alias for NewNode.
func NewSourcedNode(id NodeID, hash []byte, source Source) Node {
	return NewNode(id, hash, source)
}

// NewNodeWithSource is an alias for NewNode.
func NewNodeWithSource(id NodeID, hash []byte, source Source) Node {
	return NewNode(id, hash, source)
}

// IsPersistent reports whether the event may be stored as durable history.
func (n Node) IsPersistent() bool { return n.Source == SourcePersistent }

// Persistent reports whether the event may be stored as durable history.
func (n Node) Persistent() bool { return n.Source == SourcePersistent }

// IsEphemeral reports whether the event is only valid for one root computation.
func (n Node) IsEphemeral() bool { return n.Source == SourceEphemeral }

// Ephemeral reports whether the event is only valid for one root computation.
func (n Node) Ephemeral() bool { return n.Source == SourceEphemeral }

// Aliases for the event struct under common names.
type (
	VisitedNode    = Node
	NodeInfo       = Node
	NodeEvent      = Node
	Event          = Node
	SourcedNode    = Node
	NodeWithSource = Node
	NodeWithOrigin = Node
	SourceEvent    = Node
	Visit          = Node
)

// SourceVisitFn visits a node with its source classification.
type SourceVisitFn func(id NodeID, hash []byte, source Source)

// Aliases for source-aware function callbacks.
type (
	NodeSourceVisitFn = SourceVisitFn
	VisitSourceFn     = SourceVisitFn
	SourceVisitorFn   = SourceVisitFn
	DetailedVisitFn   = SourceVisitFn
	OriginVisitFn     = SourceVisitFn
	NodeOriginVisitFn = SourceVisitFn
)

// NodeVisitFn visits a complete sourced Node event.
type NodeVisitFn func(node Node)

// Aliases for event callbacks.
type (
	VisitNodeFn      = NodeVisitFn
	NodeVisitorFunc  = NodeVisitFn
	VisitorFunc      = NodeVisitFn
	NodeEventVisitFn = NodeVisitFn
	EventVisitFn     = NodeVisitFn
)

// NodeVisitor is implemented by types that consume sourced node events.
type NodeVisitor interface {
	VisitNode(node Node)
}

// PointerNodeVisitor is implemented by types that consume pointer node events.
type PointerNodeVisitor interface {
	VisitNode(node *Node)
}

// Visitor is an alternative interface name for sourced node events.
type Visitor interface {
	Visit(node Node)
}

// PointerVisitor is the pointer-event form of Visitor.
type PointerVisitor interface {
	Visit(node *Node)
}

// SplitVisitor receives persistent and ephemeral nodes through separate
// methods. This is an alternative to carrying Source on every event.
type SplitVisitor interface {
	VisitPersistentNode(id NodeID, hash []byte)
	VisitEphemeralNode(id NodeID, hash []byte)
}

// SplitNodeVisitor receives complete persistent and ephemeral node events
// through separate methods.
type SplitNodeVisitor interface {
	VisitPersistentNode(node Node)
	VisitEphemeralNode(node Node)
}

// VisitNode implements NodeVisitor for a NodeVisitFn.
func (f NodeVisitFn) VisitNode(node Node) { f(node) }

// Visit implements Visitor for a NodeVisitFn.
func (f NodeVisitFn) Visit(node Node) { f(node) }

// VisitNode adapts the legacy hash-only callback to sourced events. It
// deliberately ignores Source so existing consumers keep their behavior.
func (f VisitFn) VisitNode(node Node) { f(node.ID, node.Hash) }

// Visit adapts the legacy hash-only callback to the Visitor interface.
func (f VisitFn) Visit(node Node) { f(node.ID, node.Hash) }

// emit is the internal normalized callback.
type emit func(Node)

// normalizeVisitor accepts the supported callback shapes.
//
// The strongly typed callbacks VisitFn, SourceVisitFn and NodeVisitFn are the
// preferred forms. Reflection additionally supports equivalent user-declared
// function/struct shapes so source-aware callers are not coupled to one exact
// event layout.
func normalizeVisitor(visitor any) emit {
	if visitor == nil {
		return nil
	}

	switch v := visitor.(type) {
	case VisitFn:
		if v == nil {
			return nil
		}
		return func(n Node) { v(n.ID, n.Hash) }
	case func(NodeID, []byte):
		if v == nil {
			return nil
		}
		return func(n Node) { v(n.ID, n.Hash) }

	case SourceVisitFn:
		if v == nil {
			return nil
		}
		return func(n Node) { v(n.ID, n.Hash, n.Source) }
	case func(NodeID, []byte, Source):
		if v == nil {
			return nil
		}
		return func(n Node) { v(n.ID, n.Hash, n.Source) }

	case NodeVisitFn:
		if v == nil {
			return nil
		}
		return emit(v)
	case func(Node):
		if v == nil {
			return nil
		}
		return emit(v)

	case NodeVisitor:
		if v == nil {
			return nil
		}
		return v.VisitNode
	case PointerNodeVisitor:
		if v == nil {
			return nil
		}
		return func(n Node) { v.VisitNode(&n) }
	case Visitor:
		if v == nil {
			return nil
		}
		return v.Visit
	case PointerVisitor:
		if v == nil {
			return nil
		}
		return func(n Node) { v.Visit(&n) }
	case SplitVisitor:
		if v == nil {
			return nil
		}
		return func(n Node) {
			if n.Source == SourceEphemeral {
				v.VisitEphemeralNode(n.ID, n.Hash)
			} else {
				v.VisitPersistentNode(n.ID, n.Hash)
			}
		}
	case SplitNodeVisitor:
		if v == nil {
			return nil
		}
		return func(n Node) {
			if n.Source == SourceEphemeral {
				v.VisitEphemeralNode(n)
			} else {
				v.VisitPersistentNode(n)
			}
		}
	}

	rv := reflect.ValueOf(visitor)
	if !rv.IsValid() || (rv.Kind() == reflect.Func && rv.IsNil()) {
		return nil
	}
	if rv.Kind() == reflect.Func {
		return reflectFuncEmitter(rv)
	}
	if rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil
	}
	if emit, ok := reflectSplitEmitter(rv); ok {
		return emit
	}
	return reflectObjectEmitter(rv)
}

func reflectSplitEmitter(v reflect.Value) (emit, bool) {
	pNames := []string{
		"VisitPersistentNode", "VisitPersistent", "PersistentNode",
		"OnPersistentNode", "OnPersistent", "SavePersistentNode",
		"StorePersistentNode", "AddPersistentNode", "VisitDurableNode",
	}
	eNames := []string{
		"VisitEphemeralNode", "VisitEphemeral", "EphemeralNode",
		"OnEphemeralNode", "OnEphemeral", "VisitTemporaryNode",
		"TemporaryNode", "VisitTransientNode",
	}
	build := func(names []string) (func(Node), bool) {
		for _, name := range names {
			m := v.MethodByName(name)
			if !m.IsValid() {
				continue
			}
			call, ok := methodCaller(m)
			if !ok {
				continue
			}
			return call, true
		}
		return nil, false
	}
	pCall, pOK := build(pNames)
	eCall, eOK := build(eNames)
	if !pOK && !eOK {
		return nil, false
	}
	return func(n Node) {
		if n.Source == SourceEphemeral {
			if eCall != nil {
				eCall(n)
			}
		} else if pCall != nil {
			pCall(n)
		}
	}, true
}

func methodCaller(m reflect.Value) (func(Node), bool) {
	t := m.Type()
	argTypes := make([]reflect.Type, t.NumIn())
	for i := range argTypes {
		argTypes[i] = t.In(i)
		if _, ok := reflectEventArg(argTypes[i], Node{}, i, t.NumIn()); !ok {
			return nil, false
		}
	}
	return func(n Node) {
		args := make([]reflect.Value, len(argTypes))
		for i, at := range argTypes {
			a, ok := reflectEventArg(at, n, i, len(argTypes))
			if !ok {
				panic(fmt.Sprintf("compact: cannot pass sourced node to method parameter %d of type %s", i, at))
			}
			args[i] = a
		}
		m.Call(args)
	}, true
}

func reflectFuncEmitter(fn reflect.Value) emit {
	t := fn.Type()
	return func(n Node) {
		args := make([]reflect.Value, 0, t.NumIn())
		last := t.NumIn()
		if t.IsVariadic() {
			last--
		}
		for i := 0; i < last; i++ {
			pt := t.In(i)
			arg, ok := reflectEventArg(pt, n, i, t.NumIn())
			if !ok {
				panic(fmt.Sprintf("compact: cannot pass sourced node to callback parameter %d of type %s", i, pt))
			}
			args = append(args, arg)
		}
		if t.IsVariadic() {
			sliceType := t.In(t.NumIn() - 1)
			elemType := sliceType.Elem()
			slice := reflect.MakeSlice(sliceType, 0, 0)
			// Also accept a single variadic source/bool argument. Most variadic
			// callbacks in this domain are func(NodeID, []byte, ...Source).
			if arg, ok := reflectEventArg(elemType, n, t.NumIn()-1, t.NumIn()); ok {
				slice = reflect.Append(slice, arg)
			}
			args = append(args, slice)
		}
		fn.Call(args)
	}
}

func reflectObjectEmitter(v reflect.Value) emit {
	// Pointer methods are available on pointer values; value methods on both.
	for _, name := range []string{"VisitNode", "Visit", "OnNode", "Observe", "Handle", "Accept"} {
		m := v.MethodByName(name)
		if !m.IsValid() || m.Type().NumIn() == 0 {
			continue
		}
		if call, ok := methodCaller(m); ok {
			return call
		}
	}

	// Also support a function-returning method? Keep the error explicit.
	panic(fmt.Sprintf("compact: unsupported node visitor type %T", v.Interface()))
}

func reflectEventArg(t reflect.Type, n Node, index, total int) (reflect.Value, bool) {
	nodeType := reflect.TypeOf(Node{})
	if nodeType.AssignableTo(t) {
		return reflect.ValueOf(n), true
	}
	if t.Kind() == reflect.Interface && nodeType.Implements(t) {
		return reflect.ValueOf(n), true
	}

	// Common positional forms: (NodeID, hash), (NodeID, hash, source/bool),
	// and (Node, source).
	switch {
	case t == reflect.TypeOf(NodeID{}):
		return reflect.ValueOf(n.ID), true
	case t == reflect.TypeOf([]byte(nil)):
		return reflect.ValueOf(n.Hash), true
	case t == reflect.TypeOf(Source(0)):
		return reflect.ValueOf(n.Source), true
	}

	if t.Kind() == reflect.Struct {
		v := reflect.New(t).Elem()
		if fillStruct(v, n) {
			return v, true
		}
	}
	if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
		v := reflect.New(t.Elem())
		if fillStruct(v.Elem(), n) {
			return v, true
		}
	}

	// A bool or string parameter can only be the source classifier in these
	// visitor shapes, independent of its position.
	if t.Kind() == reflect.Bool || t.Kind() == reflect.String {
		if v, ok := reflectSourceValue(t, n.Source); ok {
			return v, true
		}
	}

	// Position-based fallback for primitive source classifiers.
	if total >= 3 && index == 2 {
		if v, ok := reflectSourceValue(t, n.Source); ok {
			return v, true
		}
	}
	if total == 2 && index == 1 {
		if t.Kind() == reflect.Struct || (t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct) {
			// Handled above.
		} else if v, ok := reflectSourceValue(t, n.Source); ok {
			return v, true
		}
	}
	if index == 0 && total == 1 {
		if t.Kind() == reflect.Struct || (t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct) {
			if t.Kind() == reflect.Struct {
				v := reflect.New(t).Elem()
				if fillStruct(v, n) {
					return v, true
				}
			}
		}
	}

	// Conversions for named primitive types.
	rv := reflect.ValueOf(n.Source)
	if rv.Type().ConvertibleTo(t) {
		return rv.Convert(t), true
	}
	idv := reflect.ValueOf(n.ID)
	if idv.Type().ConvertibleTo(t) {
		return idv.Convert(t), true
	}
	hv := reflect.ValueOf(n.Hash)
	if hv.Type().ConvertibleTo(t) {
		return hv.Convert(t), true
	}
	return reflect.Value{}, false
}

func reflectSourceValue(t reflect.Type, s Source) (reflect.Value, bool) {
	st := reflect.TypeOf(s)
	if st.AssignableTo(t) {
		return reflect.ValueOf(s), true
	}
	if st.ConvertibleTo(t) {
		return reflect.ValueOf(s).Convert(t), true
	}
	switch t.Kind() {
	case reflect.Bool:
		name := strings.ToLower(t.Name())
		if strings.Contains(name, "persistent") && !strings.Contains(name, "ephemeral") {
			return reflect.ValueOf(s == SourcePersistent).Convert(t), true
		}
		// The conventional bool spelling is "ephemeral".
		return reflect.ValueOf(s == SourceEphemeral).Convert(t), true
	case reflect.String:
		return reflect.ValueOf(s.String()).Convert(t), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflect.ValueOf(int(s)).Convert(t), true
	}
	return reflect.Value{}, false
}

func fillStruct(v reflect.Value, n Node) bool {
	t := v.Type()
	matched := false
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		if f.Anonymous {
			if fv.Kind() == reflect.Struct {
				if f.Type == reflect.TypeOf(Node{}) {
					fv.Set(reflect.ValueOf(n))
					matched = true
					continue
				}
				if fillStruct(fv, n) {
					matched = true
				}
			}
			continue
		}

		name := normalizeFieldName(f.Name)
		switch {
		case name == "id" || name == "nodeid" || name == "key":
			if fv.CanSet() && reflect.TypeOf(n.ID).AssignableTo(f.Type) {
				fv.Set(reflect.ValueOf(n.ID))
				matched = true
			} else if fv.CanSet() && reflect.ValueOf(n.ID).Type().ConvertibleTo(f.Type) {
				fv.Set(reflect.ValueOf(n.ID).Convert(f.Type))
				matched = true
			}
		case name == "hash" || name == "digest" || name == "value":
			if fv.CanSet() && reflect.TypeOf(n.Hash).AssignableTo(f.Type) {
				fv.Set(reflect.ValueOf(n.Hash))
				matched = true
			}
		case strings.Contains(name, "source") || strings.Contains(name, "origin") ||
			strings.Contains(name, "provenance") || name == "kind" || name == "type" ||
			strings.Contains(name, "class"):
			if fv.CanSet() {
				if sv, ok := reflectSourceValue(f.Type, n.Source); ok {
					fv.Set(sv)
					matched = true
				}
			}
		case strings.HasPrefix(name, "is") && (strings.Contains(name, "ephemeral") || strings.Contains(name, "temporary")):
			if fv.Kind() == reflect.Bool && fv.CanSet() {
				fv.SetBool(n.Source == SourceEphemeral)
				matched = true
			}
		case strings.Contains(name, "ephemeral") || strings.Contains(name, "temporary") ||
			strings.Contains(name, "transient"):
			if fv.Kind() == reflect.Bool && fv.CanSet() {
				fv.SetBool(n.Source == SourceEphemeral)
				matched = true
			}
		case strings.HasPrefix(name, "is") && strings.Contains(name, "persistent"):
			if fv.Kind() == reflect.Bool && fv.CanSet() {
				fv.SetBool(n.Source == SourcePersistent)
				matched = true
			}
		case strings.Contains(name, "persistent") || strings.Contains(name, "durable") ||
			strings.Contains(name, "committed") || strings.Contains(name, "canonical") ||
			strings.Contains(name, "perfect") || strings.Contains(name, "real"):
			if fv.Kind() == reflect.Bool && fv.CanSet() {
				fv.SetBool(n.Source == SourcePersistent)
				matched = true
			}
		}
	}
	return matched
}

func normalizeFieldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			if b.Len() > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return strings.ReplaceAll(b.String(), "__", "_")
}
