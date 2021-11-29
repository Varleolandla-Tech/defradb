// Copyright 2020 Source Inc.
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
	"context"

	"github.com/sourcenetwork/defradb/core"
	corecrdt "github.com/sourcenetwork/defradb/core/crdt"
	"github.com/sourcenetwork/defradb/merkle/clock"

	// "github.com/sourcenetwork/defradb/store"

	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
)

var (
	compFactoryFn = MerkleCRDTFactory(func(mstore core.MultiStore) MerkleCRDTInitFn {
		return func(key ds.Key) MerkleCRDT {
			return NewMerkleCompositeDAG(mstore.Datastore(), mstore.Headstore(), mstore.DAGstore(), ds.NewKey(""), key)
		}
	})
)

func init() {
	DefaultFactory.Register(core.COMPOSITE, &compFactoryFn)
}

// MerkleCompositeDAG is a MerkleCRDT implementation of the CompositeDAG
// using MerkleClocks
type MerkleCompositeDAG struct {
	*baseMerkleCRDT
	// core.ReplicatedData

	reg corecrdt.CompositeDAG

	/* Commenting because this is unused code, and the linter complains (structcheck):
	clock core.MerkleClock
	*/
}

// NewMerkleCompositeDAG creates a new instance (or loaded from DB) of a MerkleCRDT
// backed by a CompositeDAG CRDT
func NewMerkleCompositeDAG(datastore core.DSReaderWriter, headstore core.DSReaderWriter, dagstore core.DAGStore, ns, dockey ds.Key) *MerkleCompositeDAG {
	compositeDag := corecrdt.NewCompositeDAG(datastore, ns, dockey.String() /* stuff like namespace and ID */)

	// strip collection/index identifier from docKey
	headsetKey := ds.KeyWithNamespaces(dockey.List()[2:])
	clock := clock.NewMerkleClock(headstore, dagstore, headsetKey.String(), compositeDag)
	base := &baseMerkleCRDT{clock, compositeDag}

	return &MerkleCompositeDAG{
		baseMerkleCRDT: base,
		reg:            compositeDag,
	}
}

// Set sets the values of CompositeDAG.
// The value is always the object from the
// mutation operations.
func (m *MerkleCompositeDAG) Set(ctx context.Context, patch []byte, links []core.DAGLink) (cid.Cid, error) {
	// Set() call on underlying CompositeDAG CRDT
	// persist/publish delta
	delta := m.reg.Set(patch, links)
	return m.Publish(ctx, delta)
}

// Value is a no-op for a CompositeDAG
func (m *MerkleCompositeDAG) Value(ctx context.Context) ([]byte, error) {
	return m.reg.Value(ctx)
}

// Merge writes the provided delta to state using a supplied
// merge semantic
// @todo
func (m *MerkleCompositeDAG) Merge(ctx context.Context, other core.Delta, id string) error {
	return m.reg.Merge(ctx, other, id)
}
