// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package crdt

import (
	"bytes"
	"context"
	"sort"
	"strings"

	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	ipld "github.com/ipfs/go-ipld-format"
	dag "github.com/ipfs/go-merkledag"
	"github.com/ugorji/go/codec"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/errors"
)

var (
	_ core.ReplicatedData = (*CompositeDAG)(nil)
	_ core.CompositeDelta = (*CompositeDAGDelta)(nil)
)

// CompositeDAGDelta represents a delta-state update made of sub-MerkleCRDTs.
type CompositeDAGDelta struct {
	// SchemaVersionID is the schema version datastore key at the time of commit.
	//
	// It can be used to identify the collection datastructure state at time of commit.
	SchemaVersionID string
	Priority        uint64
	Data            []byte
	DocKey          []byte
	SubDAGs         []core.DAGLink
	// Status represents the status of the document. By default it is `Active`.
	// Alternatively, if can be set to `Deleted`.
	Status client.DocumentStatus
}

// GetPriority gets the current priority for this delta.
func (delta *CompositeDAGDelta) GetPriority() uint64 {
	return delta.Priority
}

// SetPriority will set the priority for this delta.
func (delta *CompositeDAGDelta) SetPriority(prio uint64) {
	delta.Priority = prio
}

// GetStatus gets the current document status for this delta.
func (delta *CompositeDAGDelta) GetStatus() client.DocumentStatus {
	return delta.Status
}

// SetStatus will set the document status for this delta.
func (delta *CompositeDAGDelta) SetStatus(status client.DocumentStatus) {
	delta.Status = status
}

// Marshal will serialize this delta to a byte array.
func (delta *CompositeDAGDelta) Marshal() ([]byte, error) {
	h := &codec.CborHandle{}
	buf := bytes.NewBuffer(nil)
	enc := codec.NewEncoder(buf, h)
	err := enc.Encode(struct {
		SchemaVersionID string
		Priority        uint64
		Data            []byte
		DocKey          []byte
		Status          uint8
	}{delta.SchemaVersionID, delta.Priority, delta.Data, delta.DocKey, delta.Status.UInt8()})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Value returns the value of this delta.
func (delta *CompositeDAGDelta) Value() any {
	return delta.Data
}

// Links returns the links for this delta.
func (delta *CompositeDAGDelta) Links() []core.DAGLink {
	return delta.SubDAGs
}

// CompositeDAG is a CRDT structure that is used to track a collection of sub MerkleCRDTs.
type CompositeDAG struct {
	store datastore.DSReaderWriter
	key   core.DataStoreKey
	// schemaVersionKey is the schema version datastore key at the time of commit.
	//
	// It can be used to identify the collection datastructure state at time of commit.
	schemaVersionKey core.CollectionSchemaVersionKey
}

func NewCompositeDAG(
	store datastore.DSReaderWriter,
	schemaVersionKey core.CollectionSchemaVersionKey,
	namespace core.Key,
	key core.DataStoreKey,
) CompositeDAG {
	return CompositeDAG{
		store:            store,
		key:              key,
		schemaVersionKey: schemaVersionKey,
	}
}

// GetSchemaID returns the schema ID of the composite DAG CRDT.
func (c CompositeDAG) ID() string {
	return c.key.ToString()
}

// GetSchemaID returns the schema ID of the composite DAG CRDT.
func (c CompositeDAG) Value(ctx context.Context) ([]byte, error) {
	return nil, nil
}

// Set applies a delta to the composite DAG CRDT. TBD
func (c CompositeDAG) Set(patch []byte, links []core.DAGLink) *CompositeDAGDelta {
	// make sure the links are sorted lexicographically by CID
	sort.Slice(links, func(i, j int) bool {
		return strings.Compare(links[i].Cid.String(), links[j].Cid.String()) < 0
	})
	return &CompositeDAGDelta{
		Data:            patch,
		DocKey:          []byte(c.key.DocKey),
		SubDAGs:         links,
		SchemaVersionID: c.schemaVersionKey.SchemaVersionId,
	}
}

// Merge implements ReplicatedData interface.
// It ensures that the object marker exists for the given key.
// If it doesn't, it adds it to the store.
func (c CompositeDAG) Merge(ctx context.Context, delta core.Delta, id string) error {
	if delta.GetStatus().IsDeleted() {
		c.store.Put(ctx, c.key.ToPrimaryDataStoreKey().ToDS(), []byte{base.DeletedObjectMarker})
		err := c.deleteWithPrefix(ctx, c.key.WithValueFlag().WithFieldId(""))
		if err != nil {
			return err
		}
		return c.deleteWithPrefix(ctx, c.key.WithPriorityFlag().WithFieldId(""))
	}

	// ensure object marker exists
	exists, err := c.store.Has(ctx, c.key.ToPrimaryDataStoreKey().ToDS())
	if err != nil {
		return err
	}
	if !exists {
		// write object marker
		return c.store.Put(ctx, c.key.ToPrimaryDataStoreKey().ToDS(), []byte{base.ObjectMarker})
	}

	return nil
}

func (c CompositeDAG) deleteWithPrefix(ctx context.Context, key core.DataStoreKey) error {
	val, err := c.store.Get(ctx, key.ToDS())
	if err != nil && !errors.Is(err, ds.ErrNotFound) {
		return err
	}
	if !errors.Is(err, ds.ErrNotFound) {
		err = c.store.Put(ctx, c.key.WithDeletedFlag().ToDS(), val)
		if err != nil {
			return err
		}
		err = c.store.Delete(ctx, key.ToDS())
		if err != nil {
			return err
		}
	}
	q := query.Query{
		Prefix: key.ToString(),
	}
	res, err := c.store.Query(ctx, q)
	for e := range res.Next() {
		if e.Error != nil {
			return err
		}
		dsKey, err := core.NewDataStoreKey(e.Key)
		if err != nil {
			return err
		}

		if dsKey.InstanceType == core.ValueKey {
			err = c.store.Put(ctx, dsKey.WithDeletedFlag().ToDS(), e.Value)
			if err != nil {
				return err
			}
		}

		err = c.store.Delete(ctx, dsKey.ToDS())
		if err != nil {
			return err
		}
	}

	return nil
}

// DeltaDecode is a typed helper to extract.
// a LWWRegDelta from a ipld.Node
// for now let's do cbor (quick to implement)
func (c CompositeDAG) DeltaDecode(node ipld.Node) (core.Delta, error) {
	delta := &CompositeDAGDelta{}
	pbNode, ok := node.(*dag.ProtoNode)
	if !ok {
		return nil, client.NewErrUnexpectedType[*dag.ProtoNode]("ipld.Node", node)
	}
	data := pbNode.Data()
	h := &codec.CborHandle{}
	dec := codec.NewDecoderBytes(data, h)
	err := dec.Decode(delta)
	if err != nil {
		return nil, err
	}

	// get links
	for _, link := range pbNode.Links() {
		if link.Name == "head" { // ignore the head links
			continue
		}

		delta.SubDAGs = append(delta.SubDAGs, core.DAGLink{
			Name: link.Name,
			Cid:  link.Cid,
		})
	}
	return delta, nil
}
