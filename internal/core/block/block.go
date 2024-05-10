// Copyright 2024 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package coreblock

import (
	"bytes"
	"sort"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/bindnode"
	"github.com/ipld/go-ipld-prime/schema"
	"github.com/multiformats/go-multicodec"

	"github.com/sourcenetwork/defradb/internal/core"
	"github.com/sourcenetwork/defradb/internal/core/crdt"
)

// Schema is the IPLD schema type that represents a `Block`.
var (
	Schema          schema.Type
	SchemaPrototype schema.TypedPrototype
)

func init() {
	Schema, SchemaPrototype = mustSetSchema(
		&Block{},
		&DAGLink{},
		&CRDT{},
		&crdt.LWWRegDelta{},
		&crdt.CompositeDAGDelta{},
		&crdt.CounterDelta[int64]{}, // Only need to call one of the CounterDelta types.
	)
}

type schemaDefinition interface {
	// IPLDSchemaBytes returns the IPLD schema representation for the type.
	IPLDSchemaBytes() []byte
}

func mustSetSchema(schemas ...schemaDefinition) (schema.Type, schema.TypedPrototype) {
	schemaBytes := make([][]byte, 0, len(schemas))
	for _, s := range schemas {
		schemaBytes = append(schemaBytes, s.IPLDSchemaBytes())
	}

	ts, err := ipld.LoadSchemaBytes(bytes.Join(schemaBytes, nil))
	if err != nil {
		panic(err)
	}
	blockSchemaType := ts.TypeByName("Block")

	// Calling bindnode.Prototype here ensure that [Block] and all the types it contains
	// are compatible with the IPLD schema defined by blockSchemaType.
	// If [Block] and `blockSchematype` do not match, this will panic.
	proto := bindnode.Prototype(&Block{}, blockSchemaType)

	return blockSchemaType, proto
}

// DAGLink represents a link to another object in a DAG.
type DAGLink struct {
	// Name is the name of the link.
	//
	// This will be either the field name of the CRDT delta or "_head" for the head link.
	Name string
	// Link is the CID link to the object.
	cidlink.Link
}

// IPLDSchemaBytes returns the IPLD schema representation for the DAGLink.
//
// This needs to match the [DAGLink] struct or [mustSetSchema] will panic on init.
func (l DAGLink) IPLDSchemaBytes() []byte {
	return []byte(`
	type DAGLink struct { 
		name	String
		link 	Link
	}`)
}

func NewDAGLink(name string, link cidlink.Link) DAGLink {
	return DAGLink{
		Name: name,
		Link: link,
	}
}

// Block is a block that contains a CRDT delta and links to other blocks.
type Block struct {
	// Delta is the CRDT delta that is stored in the block.
	Delta CRDT
	// Links are the links to other blocks in the DAG.
	Links []DAGLink
}

// IPLDSchemaBytes returns the IPLD schema representation for the block.
//
// This needs to match the [Block] struct or [mustSetSchema] will panic on init.
func (b Block) IPLDSchemaBytes() []byte {
	return []byte(`
	type Block struct {
		delta	CRDT
		links	[ DAGLink ]
	}`)
}

// New creates a new block with the given delta and links.
func New(delta core.Delta, links []DAGLink, heads ...cid.Cid) *Block {
	blockLinks := make([]DAGLink, 0, len(links)+len(heads))

	// Sort the heads lexicographically by CID.
	// We need to do this to ensure that the block is deterministic.
	sort.Slice(heads, func(i, j int) bool {
		return strings.Compare(heads[i].String(), heads[j].String()) < 0
	})
	for _, head := range heads {
		blockLinks = append(
			blockLinks,
			DAGLink{
				Name: core.HEAD,
				Link: cidlink.Link{Cid: head},
			},
		)
	}

	// Sort the links lexicographically by CID.
	// We need to do this to ensure that the block is deterministic.
	sort.Slice(links, func(i, j int) bool {
		return strings.Compare(links[i].Cid.String(), links[j].Cid.String()) < 0
	})

	blockLinks = append(blockLinks, links...)

	var crdtDelta CRDT
	switch delta := delta.(type) {
	case *crdt.LWWRegDelta:
		crdtDelta = CRDT{LWWRegDelta: delta}
	case *crdt.CompositeDAGDelta:
		crdtDelta = CRDT{CompositeDAGDelta: delta}
	case *crdt.CounterDelta[int64]:
		crdtDelta = CRDT{CounterDeltaInt: delta}
	case *crdt.CounterDelta[float64]:
		crdtDelta = CRDT{CounterDeltaFloat: delta}
	}

	return &Block{
		Links: blockLinks,
		Delta: crdtDelta,
	}
}

// GetFromBytes returns a block from encoded bytes.
func GetFromBytes(b []byte) (*Block, error) {
	block := &Block{}
	err := block.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// GetFromNode returns a block from a node.
func GetFromNode(node ipld.Node) (*Block, error) {
	block, ok := bindnode.Unwrap(node).(*Block)
	if !ok {
		return nil, NewErrNodeToBlock(node)
	}
	return block, nil
}

// Marshal encodes the delta using CBOR encoding.
func (block *Block) Marshal() (data []byte, err error) {
	b, err := ipld.Marshal(dagcbor.Encode, block, Schema)
	if err != nil {
		return nil, NewErrEncodingBlock(err)
	}
	return b, nil
}

// Unmarshal decodes the delta from CBOR encoding.
func (block *Block) Unmarshal(b []byte) error {
	_, err := ipld.Unmarshal(
		b,
		dagcbor.Decode,
		block,
		Schema,
	)
	if err != nil {
		return NewErrUnmarshallingBlock(err)
	}
	return nil
}

// GenerateNode generates an IPLD node from the block.
func (block *Block) GenerateNode() (node ipld.Node) {
	return bindnode.Wrap(block, Schema)
}

// GetLinkByName returns the link by name. It will return false if the link does not exist.
func (block *Block) GetLinkByName(name string) (cidlink.Link, bool) {
	for _, link := range block.Links {
		if link.Name == name {
			return link.Link, true
		}
	}
	return cidlink.Link{}, false
}

// GenerateLink generates a cid link for the block.
func (block *Block) GenerateLink() (cidlink.Link, error) {
	node := bindnode.Wrap(block, Schema)
	return GetLinkFromNode(node)
}

// GetLinkFromNode returns the cid link from the node.
func GetLinkFromNode(node ipld.Node) (cidlink.Link, error) {
	lsys := cidlink.DefaultLinkSystem()
	link, err := lsys.ComputeLink(GetLinkPrototype(), node)
	if err != nil {
		return cidlink.Link{}, NewErrGeneratingLink(err)
	}
	return link.(cidlink.Link), nil
}

// GetLinkPrototype returns the link prototype for the block.
func GetLinkPrototype() cidlink.LinkPrototype {
	return cidlink.LinkPrototype{Prefix: cid.Prefix{
		Version:  uint64(multicodec.Cidv1),
		Codec:    uint64(multicodec.DagCbor),
		MhType:   uint64(multicodec.Sha2_256),
		MhLength: 32,
	}}
}

// CRDT is a union type that can hold any of the CRDT deltas.
type CRDT struct {
	LWWRegDelta       *crdt.LWWRegDelta
	CompositeDAGDelta *crdt.CompositeDAGDelta
	CounterDeltaInt   *crdt.CounterDelta[int64]
	CounterDeltaFloat *crdt.CounterDelta[float64]
}

// IPLDSchemaBytes returns the IPLD schema representation for the CRDT.
//
// This needs to match the [CRDT] struct or [mustSetSchema] will panic on init.
func (c CRDT) IPLDSchemaBytes() []byte {
	return []byte(`
	type CRDT union {
		| LWWRegDelta "lww"
		| CompositeDAGDelta "composite"
		| CounterDeltaInt "counterInt"
		| CounterDeltaFloat "counterFloat"
	} representation keyed`)
}

// GetDelta returns the delta that is stored in the CRDT.
func (c CRDT) GetDelta() core.Delta {
	switch {
	case c.LWWRegDelta != nil:
		return c.LWWRegDelta
	case c.CompositeDAGDelta != nil:
		return c.CompositeDAGDelta
	case c.CounterDeltaFloat != nil:
		return c.CounterDeltaFloat
	case c.CounterDeltaInt != nil:
		return c.CounterDeltaInt
	}
	return nil
}

// GetPriority returns the priority of the delta.
func (c CRDT) GetPriority() uint64 {
	switch {
	case c.LWWRegDelta != nil:
		return c.LWWRegDelta.GetPriority()
	case c.CompositeDAGDelta != nil:
		return c.CompositeDAGDelta.GetPriority()
	case c.CounterDeltaFloat != nil:
		return c.CounterDeltaFloat.GetPriority()
	case c.CounterDeltaInt != nil:
		return c.CounterDeltaInt.GetPriority()
	}
	return 0
}

// GetFieldName returns the field name of the delta.
func (c CRDT) GetFieldName() string {
	switch {
	case c.LWWRegDelta != nil:
		return c.LWWRegDelta.FieldName
	case c.CompositeDAGDelta != nil:
		return c.CompositeDAGDelta.FieldName
	case c.CounterDeltaFloat != nil:
		return c.CounterDeltaFloat.FieldName
	case c.CounterDeltaInt != nil:
		return c.CounterDeltaInt.FieldName
	}
	return ""
}

// GetDocID returns the docID of the delta.
func (c CRDT) GetDocID() []byte {
	switch {
	case c.LWWRegDelta != nil:
		return c.LWWRegDelta.DocID
	case c.CompositeDAGDelta != nil:
		return c.CompositeDAGDelta.DocID
	case c.CounterDeltaFloat != nil:
		return c.CounterDeltaFloat.DocID
	case c.CounterDeltaInt != nil:
		return c.CounterDeltaInt.DocID
	}
	return nil
}

// GetSchemaVersionID returns the schema version ID of the delta.
func (c CRDT) GetSchemaVersionID() string {
	switch {
	case c.LWWRegDelta != nil:
		return c.LWWRegDelta.SchemaVersionID
	case c.CompositeDAGDelta != nil:
		return c.CompositeDAGDelta.SchemaVersionID
	case c.CounterDeltaFloat != nil:
		return c.CounterDeltaFloat.SchemaVersionID
	case c.CounterDeltaInt != nil:
		return c.CounterDeltaInt.SchemaVersionID
	}
	return ""
}

// GetStatus returns the status of the delta.
//
// Currently only implemented for CompositeDAGDelta.
func (c CRDT) GetStatus() uint8 {
	if c.CompositeDAGDelta != nil {
		return uint8(c.CompositeDAGDelta.Status)
	}
	return 0
}

// GetData returns the data of the delta.
//
// Currently only implemented for LWWRegDelta.
func (c CRDT) GetData() []byte {
	if c.LWWRegDelta != nil {
		return c.LWWRegDelta.Data
	}
	return nil
}
