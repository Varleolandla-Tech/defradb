// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package memory

import (
	"context"
	"sync/atomic"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
	"github.com/tidwall/btree"
)

type dsTxn struct {
	dsVersion  uint64
	txnVersion uint64
	expiresAt  time.Time
}

func byDSVersion(a, b dsTxn) bool {
	switch {
	case a.dsVersion < b.dsVersion:
		return true
	case a.dsVersion == b.dsVersion && a.txnVersion < b.txnVersion:
		return true
	default:
		return false
	}
}

type dsItem struct {
	key       string
	version   uint64
	val       []byte
	isDeleted bool
	isGet     bool
}

func byKeys(a, b dsItem) bool {
	switch {
	case a.key < b.key:
		return true
	case a.key == b.key && a.version < b.version:
		return true
	default:
		return false
	}
}

type commit struct {
	tx  *basicTxn
	err chan error
}

// Datastore uses a btree for internal storage.
type Datastore struct {
	// Latest committed version.
	version     *uint64
	values      *btree.BTreeG[dsItem]
	inFlightTxn *btree.BTreeG[dsTxn]
	close       chan struct{}
	commit      chan commit
}

var _ ds.Datastore = (*Datastore)(nil)
var _ ds.Batching = (*Datastore)(nil)
var _ ds.TxnFeature = (*Datastore)(nil)

// NewDatastore constructs an empty Datastore.
func NewDatastore(ctx context.Context) *Datastore {
	v := uint64(0)
	d := &Datastore{
		version:     &v,
		values:      btree.NewBTreeG(byKeys),
		inFlightTxn: btree.NewBTreeG(byDSVersion),
		close:       make(chan struct{}),
		commit:      make(chan commit),
	}
	go d.purgeOldVersions(ctx)
	go d.commitHandler(ctx)
	return d
}

func (d *Datastore) getVersion() uint64 {
	return atomic.LoadUint64(d.version)
}

func (d *Datastore) nextVersion() uint64 {
	return atomic.AddUint64(d.version, 1)
}

// Batch return a ds.Batch datastore based on Datastore.
func (d *Datastore) Batch(ctx context.Context) (ds.Batch, error) {
	return d.newBasicBatch(), nil
}

// newBasicBatch returns a ds.Batch datastore.
func (d *Datastore) newBasicBatch() ds.Batch {
	return &basicBatch{
		ops: make(map[ds.Key]op),
		ds:  d,
	}
}

func (d *Datastore) Close() error {
	d.close <- struct{}{}
	return nil
}

// Delete implements ds.Delete.
func (d *Datastore) Delete(ctx context.Context, key ds.Key) (err error) {
	tx := d.newTransaction(false)
	err = tx.Delete(ctx, key)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Datastore) get(ctx context.Context, key ds.Key, version uint64) dsItem {
	result := dsItem{}
	d.values.Descend(dsItem{key: key.String(), version: version}, func(item dsItem) bool {
		if key.String() == item.key {
			result = item
		}
		// We only care about the last version so we stop iterating right away by returning false.
		return false
	})
	return result
}

// Get implements ds.Get.
func (d *Datastore) Get(ctx context.Context, key ds.Key) (value []byte, err error) {
	result := d.get(ctx, key, d.getVersion())
	if result.key == "" || result.isDeleted {
		return nil, ds.ErrNotFound
	}
	return result.val, nil
}

// GetSize implements ds.GetSize.
func (d *Datastore) GetSize(ctx context.Context, key ds.Key) (size int, err error) {
	result := d.get(ctx, key, d.getVersion())
	if result.key == "" || result.isDeleted {
		return 0, ds.ErrNotFound
	}
	return len(result.val), nil
}

// Has implements ds.Has.
func (d *Datastore) Has(ctx context.Context, key ds.Key) (exists bool, err error) {
	result := d.get(ctx, key, d.getVersion())
	return result.key != "" && !result.isDeleted, nil
}

// NewTransaction return a ds.Txn datastore based on Datastore.
func (d *Datastore) NewTransaction(ctx context.Context, readOnly bool) (ds.Txn, error) {
	return d.newTransaction(readOnly), nil
}

// newTransaction returns a ds.Txn datastore.
func (d *Datastore) newTransaction(readOnly bool) ds.Txn {
	v := d.getVersion()
	d.inFlightTxn.Set(dsTxn{v, v + 1, time.Now().Add(1 * time.Hour)})
	return &basicTxn{
		ops:       btree.NewBTreeG(byKeys),
		ds:        d,
		readOnly:  readOnly,
		dsVersion: &v,
	}
}

// Put implements ds.Put.
func (d *Datastore) Put(ctx context.Context, key ds.Key, value []byte) (err error) {
	tx := d.newTransaction(false)
	err = tx.Put(ctx, key, value)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Query implements ds.Query.
func (d *Datastore) Query(ctx context.Context, q dsq.Query) (dsq.Results, error) {
	re := make([]dsq.Entry, 0, d.values.Height())
	iter := d.values.Iter()
	for iter.Next() {
		// fast forward to last inserted version
		item := iter.Item()
		for iter.Next() {
			if item.key == iter.Item().key {
				item = iter.Item()
				continue
			}
			iter.Prev()
			break
		}

		if item.isDeleted {
			continue
		}

		e := dsq.Entry{Key: item.key, Size: len(item.val)}
		if !q.KeysOnly {
			e.Value = item.val
		}

		re = append(re, e)
	}
	iter.Release()

	r := dsq.ResultsWithEntries(q, re)
	r = dsq.NaiveQueryApply(q, r)
	return r, nil
}

// Sync implements ds.Sync.
func (d *Datastore) Sync(ctx context.Context, prefix ds.Key) error {
	return nil
}

// purgeOldVersions will execute the purge once a day or when explicitly requested.
func (d *Datastore) purgeOldVersions(ctx context.Context) {
	dbStartTime := time.Now()
	nextCompression := time.Date(dbStartTime.Year(), dbStartTime.Month(), dbStartTime.Day()+1,
		0, 0, 0, 0, dbStartTime.Location())

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.close:
			return
		case <-time.After(time.Until(nextCompression)):
			d.executePurge(ctx)
			now := time.Now()
			nextCompression = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		}
	}
}

func (d *Datastore) executePurge(ctx context.Context) {
	// purging bellow this version
	v := d.getVersion()
	if dsTxn, hasMin := d.inFlightTxn.Min(); hasMin {
		v = dsTxn.dsVersion
	}

	for {
		itemsToDelete := []dsItem{}
		iter := d.values.Iter()
		iter.Next()
		item := iter.Item()

		// fast forward to last inserted version and delete versions before it
		total := 0
		for iter.Next() {
			if iter.Item().version > v {
				continue
			}
			if item.key == iter.Item().key {
				itemsToDelete = append(itemsToDelete, item)
				total++
			}
			item = iter.Item()
			// we don't want to delete more than 1000 items at a time
			// to prevent loading too much into memory
			if total >= 1000 {
				break
			}
		}
		iter.Release()

		if total == 0 {
			return
		}

		for _, i := range itemsToDelete {
			d.values.Delete(i)
		}
	}
}

func (d *Datastore) commitHandler(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c, open := <-d.commit:
			if !open {
				return
			}
			err := c.tx.checkForConflicts(ctx)
			if err != nil {
				c.err <- err
				continue
			}
			iter := c.tx.ops.Iter()
			v := d.nextVersion()
			for iter.Next() {
				if iter.Item().isGet {
					continue
				}
				item := iter.Item()
				item.version = v
				d.values.Set(item)
			}
			iter.Release()
			close(c.err)
		}
	}
}

func (d *Datastore) clearOldInFlightTxn(ctx context.Context) {
	if d.inFlightTxn.Height() == 0 {
		return
	}

	now := time.Now()
	for {
		itemsToDelete := []dsTxn{}
		iter := d.inFlightTxn.Iter()

		total := 0
		for iter.Next() {
			if now.After(iter.Item().expiresAt) {
				itemsToDelete = append(itemsToDelete, iter.Item())
				total++
			}
			// we don't want to delete more than 1000 items at a time
			// to prevent loading too much into memory
			if total >= 1000 {
				break
			}
		}
		iter.Release()

		if total == 0 {
			return
		}

		for _, i := range itemsToDelete {
			d.inFlightTxn.Delete(i)
		}
	}
}
