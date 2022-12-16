// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package datastore

import (
	"context"

	ds "github.com/ipfs/go-datastore"

	"github.com/sourcenetwork/defradb/datastore/iterable"
)

// Txn is a common interface to the db.Txn struct.
type Txn interface {
	MultiStore

	IsBatch() bool

	// Commit finalizes a transaction, attempting to commit it to the Datastore.
	// May return an error if the transaction has gone stale. The presence of an
	// error is an indication that the data was not committed to the Datastore.
	Commit(ctx context.Context) error
	// Discard throws away changes recorded in a transaction without committing
	// them to the underlying Datastore. Any calls made to Discard after Commit
	// has been successfully called will have no effect on the transaction and
	// state of the Datastore, making it safe to defer.
	Discard(ctx context.Context)

	OnSuccess(fn func())
	OnError(fn func())
}

type txn struct {
	t ds.Txn
	MultiStore
	isBatch bool

	successFns []func()
	errorFns   []func()
}

var _ Txn = (*txn)(nil)

// NOTE: rootstore temporarily set to any and should be changed when the rootstore is changed to
// support ds.TxnDatastore
func NewTxnFrom(ctx context.Context, rootstore any, readonly bool) (Txn, error) {
	// check if our datastore natively supports iterable transaction, transactions or batching
	if iterableTxnStore, ok := rootstore.(iterable.IterableTxnDatastore); ok {
		rootTxn, err := iterableTxnStore.NewIterableTransaction(ctx, readonly)
		if err != nil {
			return nil, err
		}
		multistore := MultiStoreFrom(rootTxn)
		return &txn{
			rootTxn,
			multistore,
			false,
			[]func(){},
			[]func(){},
		}, nil
	}

	txnStore := rootstore.(ds.TxnDatastore)
	rootTxn, err := txnStore.NewTransaction(ctx, readonly)
	if err != nil {
		return nil, err
	}

	root := AsDSReaderWriter(txnStore)
	multistore := MultiStoreFrom(root)
	return &txn{
		rootTxn,
		multistore,
		false,
		[]func(){},
		[]func(){},
	}, nil
}

func (t *txn) Commit(ctx context.Context) error {
	if err := t.t.Commit(ctx); err != nil {
		t.runErrorFns(ctx)
		return err
	}
	t.runSuccessFns(ctx)
	return nil
}

func (t *txn) Discard(ctx context.Context) {
	t.t.Discard(ctx)
}

func (txn *txn) OnSuccess(fn func()) {
	if fn == nil {
		return
	}
	txn.successFns = append(txn.successFns, fn)
}

func (txn *txn) OnError(fn func()) {
	if fn == nil {
		return
	}
	txn.errorFns = append(txn.errorFns, fn)
}

func (txn *txn) runErrorFns(ctx context.Context) {
	for _, fn := range txn.errorFns {
		fn()
	}
}

func (txn *txn) runSuccessFns(ctx context.Context) {
	for _, fn := range txn.successFns {
		fn()
	}
}

func (txn *txn) IsBatch() bool {
	return txn.isBatch
}

// Shim to make ds.Txn support ds.Datastore
type ShimTxnStore struct {
	ds.Txn
}

func (ts ShimTxnStore) Sync(ctx context.Context, prefix ds.Key) error {
	return ts.Txn.Commit(ctx)
}

func (ts ShimTxnStore) Close() error {
	ts.Discard(context.TODO())
	return nil
}

// shim to make ds.Batch implement ds.Datastore
type ShimBatcherTxn struct {
	ds.Read
	ds.Batch
}

func (ShimBatcherTxn) Discard(_ context.Context) {
	// noop
}
