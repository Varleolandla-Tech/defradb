// Copyright 2021 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package store

import (
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/db/base"

	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/namespace"
)

type multistore struct {
	root core.DSReaderWriter
	data core.DSReaderWriter
	head core.DSReaderWriter
	// block core.DSReaderWriter
	dag core.DAGStore
}

func MultiStoreFrom(rootstore ds.Datastore) core.MultiStore {
	ms := &multistore{root: rootstore}
	ms.data = namespace.Wrap(rootstore, base.DataStoreKey)
	ms.head = namespace.Wrap(rootstore, base.HeadStoreKey)
	block := namespace.Wrap(rootstore, base.BlockStoreKey)
	ms.dag = NewDAGStore(block)

	return ms
}

// Datastore implements core.Multistore
func (ms multistore) Datastore() core.DSReaderWriter {
	return ms.data
}

// Headstore implements core.Multistore
func (ms multistore) Headstore() core.DSReaderWriter {
	return ms.head
}

// DAGstore implements core.Multistore
func (ms multistore) DAGstore() core.DAGStore {
	return ms.dag
}
