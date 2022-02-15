// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package db

import (
	"context"
	"errors"
	"fmt"

	block "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	query "github.com/ipfs/go-datastore/query"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	dag "github.com/ipfs/go-merkledag"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/document"
	"github.com/sourcenetwork/defradb/document/key"
	"github.com/sourcenetwork/defradb/merkle/clock"
	"github.com/sourcenetwork/defradb/query/graphql/parser"
)

var (
	ErrInvalidDeleteTarget = errors.New("The doc delete targeter is an unknown type")
	ErrDeleteTargetEmpty   = errors.New("The doc delete targeter cannot be empty")
	ErrDeleteEmpty         = errors.New("The doc delete cannot be empty")
)

// DeleteWith deletes a target document. Target can be a Filter statement,
//  a single docKey, a single document, an array of docKeys, or an array of documents.
// If you want more type safety, use the respective typed versions of Delete.
// Eg: DeleteWithFilter or DeleteWithKey
func (c *Collection) DeleteWith(
	ctx context.Context,
	target interface{},
	opts ...client.DeleteOpt) error {

	switch t := target.(type) {

	case string, map[string]interface{}, *parser.Filter:
		_, err := c.DeleteWithFilter(ctx, t, opts...)
		return err

	case key.DocKey:
		_, err := c.DeleteWithKey(ctx, t, opts...)
		return err

	case []key.DocKey:
		_, err := c.DeleteWithKeys(ctx, t, opts...)
		return err

	case *document.SimpleDocument:
		return c.DeleteWithDoc(t, opts...)

	case []*document.SimpleDocument:
		return c.DeleteWithDocs(t, opts...)

	default:
		return ErrInvalidDeleteTarget

	}
}

// DeleteWithKey deletes using a DocKey to target a single document for delete.
func (c *Collection) DeleteWithKey(ctx context.Context, key key.DocKey, opts ...client.DeleteOpt) (*client.DeleteResult, error) {

	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return nil, err
	}

	defer c.discardImplicitTxn(ctx, txn)

	res, err := c.deleteWithKey(ctx, txn, key, opts...)
	if err != nil {
		return nil, err
	}

	return res, c.commitImplicitTxn(ctx, txn)
}

// DeleteWithKeys is the same as DeleteWithKey but accepts multiple keys as a slice.
func (c *Collection) DeleteWithKeys(ctx context.Context, keys []key.DocKey, opts ...client.DeleteOpt) (*client.DeleteResult, error) {

	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return nil, err
	}

	defer c.discardImplicitTxn(ctx, txn)

	res, err := c.deleteWithKeys(ctx, txn, keys, opts...)
	if err != nil {
		return nil, err
	}

	return res, c.commitImplicitTxn(ctx, txn)
}

func (c *Collection) deleteWithKeys(ctx context.Context, txn core.Txn, keys []key.DocKey, opts ...client.DeleteOpt) (*client.DeleteResult, error) {

	keysDeleted := []string{}

	for _, key := range keys {

		// Check this docKey actually exists.
		found, err := c.exists(ctx, txn, key)

		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrDocumentNotFound
		}

		// Apply the function that will perform the full deletion of this document.
		err = c.applyFullDelete(ctx, txn, key)
		if err != nil {
			return nil, err
		}

		// Add this deleted key to our list.
		keysDeleted = append(keysDeleted, key.String())
	}

	// Upon successfull deletion, record a summary.
	results := &client.DeleteResult{
		Count:   int64(len(keysDeleted)),
		DocKeys: keysDeleted,
	}

	return results, nil
}

func (c *Collection) deleteWithKey(ctx context.Context, txn core.Txn, key key.DocKey, opts ...client.DeleteOpt) (*client.DeleteResult, error) {
	// Check the docKey we have been given to delete with actually has a corresponding
	//  document (i.e. document actually exists in the collection).
	found, err := c.exists(ctx, txn, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrDocumentNotFound
	}

	// Apply the function that will perform the full deletion of the document.
	err = c.applyFullDelete(ctx, txn, key)
	if err != nil {
		return nil, err
	}

	// Upon successfull deletion, record a summary.
	results := &client.DeleteResult{
		Count:   1,
		DocKeys: []string{key.String()},
	}

	return results, nil
}

type dagDeleter struct {
	bstore core.DAGStore
	// queue *list.List
}

func newDagDeleter(bstore core.DAGStore) dagDeleter {
	return dagDeleter{
		bstore: bstore,
	}
}

// Here is what our db stores look like:
//   /db
//   -> block /blocks => /db/blocks
//   -> datastore /data => /db/data
//   -> headstore /heads => /db/heads
//   -> systemstore /system => /db/system
// For the delete operation we are concerned with:
//   1) Deleting the actual blocks (blockstore).
//   2) Deleting datastore state.
//   3) Deleting headstore state.
func (c *Collection) applyFullDelete(
	ctx context.Context,
	txn core.Txn, dockey key.DocKey) error {

	// Check the docKey we have been given to delete with actually has a corresponding
	//  document (i.e. document actually exists in the collection).
	found, err := c.exists(ctx, txn, dockey)
	if err != nil {
		return err
	}
	if !found {
		return ErrDocumentNotFound
	}

	// 1. =========================== Delete blockstore state ===========================
	// blocks: /db/blocks/CIQSDFKLJGHFKLSJGHHJKKLGHGLHSKLHKJGS => KLJSFHGLKJFHJKDLGKHDGLHGLFDHGLFDGKGHL

	// Covert dockey to compositeKey as follows:
	//  * dockey: bae-kljhLKHJG-lkjhgkldjhlzkdf-kdhflkhjsklgh-kjdhlkghjs
	//  => compositeKey: bae-kljhLKHJG-lkjhgkldjhlzkdf-kdhflkhjsklgh-kjdhlkghjs/C
	compositeKey := dockey.Key.ChildString(core.COMPOSITE_NAMESPACE)
	headset := clock.NewHeadSet(txn.Headstore(), compositeKey)

	// Get all the heads (cids).
	heads, _, err := headset.List(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get document heads: %w", err)
	}

	dagDel := newDagDeleter(txn.DAGstore())
	// Delete DAG of all heads (and the heads themselves)
	for _, head := range heads {
		if err = dagDel.run(ctx, head); err != nil {
			return err
		}
	} // ================================================ Successfully deleted the blocks

	// 2. =========================== Delete datastore state ============================
	dataQuery := query.Query{
		Prefix:   c.getPrimaryIndexDocKey(dockey.Key).String(),
		KeysOnly: true,
	}
	dataResult, err := txn.Datastore().Query(ctx, dataQuery)
	for e := range dataResult.Next() {
		if e.Error != nil {
			return err
		}

		// docs: https://pkg.go.dev/github.com/ipfs/go-datastore
		err = txn.Datastore().Delete(ctx, ds.NewKey(e.Key))
		if err != nil {
			return err
		}
	}
	// Delete the parent marker key for this document.
	err = txn.Datastore().Delete(ctx, c.getPrimaryIndexDocKey(dockey.Key).Instance("v"))
	if err != nil {
		return err
	}
	// ======================== Successfully deleted the datastore state of this document

	// 3. =========================== Delete headstore state ===========================
	headQuery := query.Query{
		Prefix:   dockey.Key.String(),
		KeysOnly: true,
	}
	headResult, err := txn.Headstore().Query(ctx, headQuery)
	for e := range headResult.Next() {
		if e.Error != nil {
			return err
		}
		err = txn.Headstore().Delete(ctx, ds.NewKey(e.Key))
		if err != nil {
			return err
		}
	} // ====================== Successfully deleted the headstore state of this document

	return nil
}

func (d dagDeleter) run(ctx context.Context, targetCid cid.Cid) error {
	// Validate the cid.
	if targetCid == cid.Undef {
		return nil
	}

	// Get the block using the cid.
	block, err := d.bstore.Get(ctx, targetCid)
	if err == blockstore.ErrNotFound {
		// If we have multiple heads corresponding to a dockey, one of the heads
		//  could have already deleted the parantal dag chain.
		// Example: in the diagram below, HEAD#1 with cid1 deleted (represented by `:x`)
		//          all the parental nodes. Currently HEAD#2 goes to delete
		//          itself (represented by `:d`) and it's parental nodes, but as we see
		//          the parents were already deleted by HEAD#1 so we just stop there.
		//
		//                                     | --> (E:x) HEAD#1->cid1
		// (A:x) --> (B:x) --> (C:x) --> (D:x) |
		//                                     | --> (F:d) HEAD#2->cid2
		return nil

	} else if err != nil {
		return err
	}

	// Attempt deleting the current block and it's links (in a mutally recursive fashion.)
	return d.delete(ctx, targetCid, block)
}

//  (ipld.Block(ipldProtobufNode{Data: (cbor(crdt deltaPayload)), Links: (_head => parentCid, fieldName => fieldCid)))
func (d dagDeleter) delete(
	ctx context.Context,
	targetCid cid.Cid,
	targetBlock block.Block) error {

	targetNode, err := dag.DecodeProtobuf(targetBlock.RawData())
	if err != nil {
		return err
	}

	// delete current block
	if err := d.bstore.DeleteBlock(ctx, targetCid); err != nil {
		return err
	}

	for _, link := range targetNode.Links() {
		// Call run on all the links (eventually delete is called on them too.)
		if err := d.run(ctx, link.Cid); err != nil {
			return err
		}
	}

	return nil
}

// =================================== UNIMPLEMENTED ===================================

// DeleteWithFilter deletes using a filter to target documents for delete.
func (c *Collection) DeleteWithFilter(ctx context.Context, filter interface{}, opts ...client.DeleteOpt) (*client.DeleteResult, error) {
	return nil, nil
}

// DeleteWithDoc deletes targeting the supplied document.
func (c *Collection) DeleteWithDoc(doc *document.SimpleDocument, opts ...client.DeleteOpt) error {
	return nil
}

// DeleteWithDocs deletes all the supplied documents in the slice.
func (c *Collection) DeleteWithDocs(docs []*document.SimpleDocument, opts ...client.DeleteOpt) error {
	return nil
}

//nolint:unused
func (c *Collection) deleteWithFilter(ctx context.Context, txn core.Txn, filter interface{}, opts ...client.DeleteOpt) (*client.DeleteResult, error) {
	return nil, nil
}
