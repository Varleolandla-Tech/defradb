// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package clock

import (
	"context"
	"testing"

	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/core/crdt"
	"github.com/sourcenetwork/defradb/datastore"

	cid "github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	mh "github.com/multiformats/go-multihash"
)

func newDS() ds.Datastore {
	return ds.NewMapDatastore()
}

func newTestMerkleClock() *MerkleClock {
	s := newDS()

	rw := datastore.AsDSReaderWriter(s)
	multistore := datastore.MultiStoreFrom(rw)
	reg := crdt.NewLWWRegister(rw, core.DataStoreKey{})
	return NewMerkleClock(multistore.Headstore(), multistore.DAGstore(), core.HeadStoreKey{DocKey: "dockey", FieldId: "1"}, reg).(*MerkleClock)
}

func TestNewMerkleClock(t *testing.T) {
	s := newDS()
	rw := datastore.AsDSReaderWriter(s)
	multistore := datastore.MultiStoreFrom(rw)
	reg := crdt.NewLWWRegister(rw, core.DataStoreKey{})
	clk := NewMerkleClock(multistore.Headstore(), multistore.DAGstore(), core.HeadStoreKey{}, reg).(*MerkleClock)

	if clk.headstore != multistore.Headstore() {
		t.Error("MerkleClock store not correctly set")
	} else if clk.headset.store == nil {
		t.Error("MerkleClock head set not correctly set")
	} else if clk.crdt == nil {
		t.Error("MerkleClock CRDT not correctly set")
	}
}

func TestMerkleClockPutBlock(t *testing.T) {
	ctx := context.Background()
	clk := newTestMerkleClock()
	delta := &crdt.LWWRegDelta{
		Data: []byte("test"),
	}
	node, err := clk.putBlock(ctx, nil, 0, delta)
	if err != nil {
		t.Errorf("Failed to putBlock, err: %v", err)
	}

	if len(node.Links()) != 0 {
		t.Errorf("Node links should be empty. Have %v, want %v", len(node.Links()), 0)
		return
	}

	// @todo Add DagSyncer check to tests
	// @body Once we add the DagSyncer to the MerkleClock implementation it needs to be
	// tested as well here.
}

func TestMerkleClockPutBlockWithHeads(t *testing.T) {
	ctx := context.Background()
	clk := newTestMerkleClock()
	delta := &crdt.LWWRegDelta{
		Data: []byte("test"),
	}
	pref := cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   mh.SHA2_256,
		MhLength: -1, // default length
	}

	// And then feed it some data
	c, err := pref.Sum([]byte("Hello World!"))
	if err != nil {
		t.Error("Failed to create new head CID:", err)
		return
	}
	heads := []cid.Cid{c}
	node, err := clk.putBlock(ctx, heads, 0, delta)
	if err != nil {
		t.Error("Failed to putBlock with heads:", err)
		return
	}

	if len(node.Links()) != 1 {
		t.Errorf("putBlock has incorrect number of heads. Have %v, want %v", len(node.Links()), 1)
	}
}

func TestMerkleClockAddDAGNode(t *testing.T) {
	ctx := context.Background()
	clk := newTestMerkleClock()
	delta := &crdt.LWWRegDelta{
		Data: []byte("test"),
	}

	_, _, err := clk.AddDAGNode(ctx, delta)
	if err != nil {
		t.Error("Failed to add dag node:", err)
		return
	}
}

func TestMerkleClockAddDAGNodeWithHeads(t *testing.T) {
	ctx := context.Background()
	clk := newTestMerkleClock()
	delta := &crdt.LWWRegDelta{
		Data: []byte("test1"),
	}

	_, _, err := clk.AddDAGNode(ctx, delta)
	if err != nil {
		t.Error("Failed to add dag node:", err)
		return
	}

	delta2 := &crdt.LWWRegDelta{
		Data: []byte("test2"),
	}

	_, _, err = clk.AddDAGNode(ctx, delta2)
	if err != nil {
		t.Error("Failed to add second dag node with err:", err)
		return
	}

	if delta.GetPriority() != 1 && delta2.GetPriority() != 2 {
		t.Errorf(
			"AddDAGNOde failed with incorrect delta priority vals, want (%v) (%v), have (%v) (%v)",
			1,
			2,
			delta.GetPriority(),
			delta2.GetPriority(),
		)
	}

	// check if lww state is correct (val is test2)
	// check if head/blockstore state is correct (one head, two blocks)
	nHeads, err := clk.headset.Len(ctx)
	if err != nil {
		t.Error("Error getting MerkleClock heads size:", err)
		return
	}
	if nHeads != 1 {
		t.Errorf("Incorrect number of heads of current clock state, have %v, want %v", nHeads, 1)
		return
	}

	numBlocks := 0
	cids, err := clk.dagstore.AllKeysChan(ctx)
	if err != nil {
		t.Error("Failed to get blockstore content for merkle clock:", err)
		return
	}
	for range cids {
		numBlocks++
	}
	if numBlocks != 2 {
		t.Errorf("Incorrect number of blocks in clock state, have %v, want %v", numBlocks, 2)
		return
	}
}

// func TestMerkleClockProcessNode(t *testing.T) {
// 	t.Error("Test not implemented")
// }

// func TestMerkleClockProcessNodeWithHeads(t *testing.T) {
// 	t.Error("Test not implemented")
// }
