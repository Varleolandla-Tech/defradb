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
	"context"

	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/logging"
)

var (
	log = logging.MustNewLogger("defra.merklecrdt")
)

// MerkleCRDT is the implementation of a Merkle Clock along with a
// CRDT payload. It implements the ReplicatedData interface
// so it can be merged with any given semantics.
type MerkleCRDT interface {
	core.ReplicatedData
	Clock() core.MerkleClock
}

var (
	// defaultMerkleCRDTs                     = make(map[Type]MerkleCRDTFactory)
	_ core.ReplicatedData = (*baseMerkleCRDT)(nil)
)

// baseMerkleCRDT handles the MerkleCRDT overhead functions that aren't CRDT specific like the mutations and state
// retrieval functions. It handles creating and publishing the CRDT DAG with the help of the MerkleClock.
type baseMerkleCRDT struct {
	clock core.MerkleClock
	crdt  core.ReplicatedData

	updateChannel client.UpdateChannel
}

func (base *baseMerkleCRDT) Clock() core.MerkleClock {
	return base.clock
}

func (base *baseMerkleCRDT) Merge(ctx context.Context, other core.Delta, id string) error {
	return base.crdt.Merge(ctx, other, id)
}

func (base *baseMerkleCRDT) DeltaDecode(node ipld.Node) (core.Delta, error) {
	return base.crdt.DeltaDecode(node)
}

func (base *baseMerkleCRDT) Value(ctx context.Context) ([]byte, error) {
	return base.crdt.Value(ctx)
}

func (base *baseMerkleCRDT) ID() string {
	return base.crdt.ID()
}

// Publishes the delta to state.
func (base *baseMerkleCRDT) Publish(
	ctx context.Context,
	delta core.Delta,
) (cid.Cid, ipld.Node, error) {
	log.Debug(ctx, "Processing CRDT state", logging.NewKV("DocKey", base.crdt.ID()))
	c, nd, err := base.clock.AddDAGNode(ctx, delta)
	if err != nil {
		return cid.Undef, nil, err
	}
	return c, nd, nil
}

func (base *baseMerkleCRDT) Broadcast(ctx context.Context, nd ipld.Node, delta core.Delta) error {
	if !base.updateChannel.HasValue() {
		return nil
	}

	dockey := core.NewDataStoreKey(base.crdt.ID()).DocKey

	c := nd.Cid()
	netdelta, ok := delta.(core.NetDelta)
	if !ok {
		return errors.New("Can't broadcast a delta payload that doesn't implement core.NetDelta")
	}

	base.updateChannel.Value().Publish(
		client.UpdateEvent{
			DocKey:   dockey,
			Cid:      c,
			SchemaID: netdelta.GetSchemaID(),
			Block:    nd,
			Priority: netdelta.GetPriority(),
		},
	)

	return nil
}
