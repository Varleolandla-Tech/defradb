// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package fetcher

import (
	"bytes"
	"context"
	"errors"

	dsq "github.com/ipfs/go-datastore/query"
	"github.com/sourcenetwork/defradb/datastores/iterable"

	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/document"
)

/*
var DocumentFetcher DocumentFetcher = &Fetcher{}
DocumentFetcher.Init()
*/
// type DocumentFetcher interface {
// 	Init(col *base.CollectionDescription, index *base.IndexDescription, fields []*base.FieldDescription, reverse bool) error
// 	Start(txn core.Txn, spans core.Spans) error
// 	FetchNext() (*document.EncodedDocument, error)
// 	FetchNextDecoded() (*document.Document, error)
// }

// var (
// 	_ DocumentFetcher = &DocFetcher{}
// )

type DocumentFetcher struct {
	col     *base.CollectionDescription
	index   *base.IndexDescription
	reverse bool

	txn          core.Txn
	spans        core.Spans
	order        []dsq.Order
	uniqueSpans  map[core.Span]struct{} // nolint:structcheck,unused
	curSpanIndex int

	schemaFields map[uint32]base.FieldDescription
	fields       []*base.FieldDescription

	doc         *document.EncodedDocument
	decodedDoc  *document.Document
	initialized bool

	kv            *core.KeyValue
	kvIter        iterable.Iterator
	kvResultsIter dsq.Results
	kvEnd         bool

	indexKey []byte
}

// Init implements DocumentFetcher
func (df *DocumentFetcher) Init(col *base.CollectionDescription, index *base.IndexDescription, fields []*base.FieldDescription, reverse bool) error {
	if col.Schema.IsEmpty() {
		return errors.New("DocumentFetcher must be given a schema")
	}

	df.col = col
	df.index = index
	df.fields = fields
	df.reverse = reverse
	df.initialized = true
	df.doc = new(document.EncodedDocument)
	df.doc.Schema = &col.Schema
	df.kvResultsIter = nil
	df.kvIter = nil

	df.schemaFields = make(map[uint32]base.FieldDescription)
	for _, field := range col.Schema.Fields {
		df.schemaFields[uint32(field.ID)] = field
	}
	return nil
}

// Start implements DocumentFetcher
func (df *DocumentFetcher) Start(ctx context.Context, txn core.Txn, spans core.Spans) error {
	if df.col == nil {
		return errors.New("DocumentFetcher cannot be started without a CollectionDescription")
	}
	if df.doc == nil {
		return errors.New("DocumentFetcher cannot be started without an initialized document obect")
	}
	if df.index == nil {
		return errors.New("DocumentFetcher cannot be started without a IndexDescription")
	}
	//@todo: Handle fields Description
	// check spans
	numspans := len(spans)
	var uniqueSpans core.Spans
	if numspans == 0 { // no specified spans so create a prefix scan key for the entire collection/index
		start := base.MakeIndexPrefixKey(df.col, df.index)
		uniqueSpans = core.Spans{core.NewSpan(start, start.PrefixEnd())}
	} else {
		uniqueSpans = spans.MergeAscending()
		if df.reverse {
			for i, j := 0, len(uniqueSpans)-1; i < j; i, j = i+1, j-1 {
				uniqueSpans[i], uniqueSpans[j] = uniqueSpans[j], uniqueSpans[i]
			}
		}
	}

	df.indexKey = nil
	df.spans = uniqueSpans
	df.curSpanIndex = -1
	df.txn = txn

	if df.reverse {
		df.order = []dsq.Order{dsq.OrderByKeyDescending{}}
	} else {
		df.order = []dsq.Order{dsq.OrderByKey{}}
	}

	_, err := df.startNextSpan(ctx)
	return err
}

func (df *DocumentFetcher) startNextSpan(ctx context.Context) (bool, error) {
	nextSpanIndex := df.curSpanIndex + 1
	if nextSpanIndex >= len(df.spans) {
		return false, nil
	}

	var err error
	if df.kvIter == nil {
		df.kvIter, err = df.txn.GetIterator(dsq.Query{
			Orders: df.order,
		})
	}
	if err != nil {
		return false, err
	}

	if df.kvResultsIter != nil {
		err = df.kvResultsIter.Close()
		if err != nil {
			return false, err
		}
	}

	span := df.spans[nextSpanIndex]
	df.kvResultsIter, err = df.kvIter.IteratePrefix(ctx, span.Start().ToDS(), span.End().ToDS())
	if err != nil {
		return false, err
	}
	df.curSpanIndex = nextSpanIndex

	_, err = df.nextKey(ctx)
	return err == nil, err
}

func (df *DocumentFetcher) KVEnd() bool {
	return df.kvEnd
}

func (df *DocumentFetcher) KV() *core.KeyValue {
	return df.kv
}

func (df *DocumentFetcher) NextKey(ctx context.Context) (docDone bool, err error) {
	return df.nextKey(ctx)
}

func (df *DocumentFetcher) NextKV() (iterDone bool, kv *core.KeyValue, err error) {
	return df.nextKV()
}

func (df *DocumentFetcher) ProcessKV(kv *core.KeyValue) error {
	return df.processKV(kv)
}

// nextKey gets the next kv. It sets both kv and kvEnd internally.
// It returns true if the current doc is completed
func (df *DocumentFetcher) nextKey(ctx context.Context) (docDone bool, err error) {
	// get the next kv from nextKV()
	for {
		docDone, df.kv, err = df.nextKV()
		// handle any internal errors
		if err != nil {
			return false, err
		}
		df.kvEnd = docDone
		if df.kvEnd {
			hasNextSpan, err := df.startNextSpan(ctx)
			if err != nil {
				return false, err
			}
			if hasNextSpan {
				return true, nil
			}
			return true, nil
		}

		// skip if we are iterating through a non value kv pair
		if df.kv.Key.Name() != "v" {
			continue
		}

		// skip object markers
		if bytes.Equal(df.kv.Value, []byte{base.ObjectMarker}) {
			continue
		}

		// check if we've crossed document boundries
		if df.indexKey != nil && !bytes.HasPrefix(df.kv.Key.Bytes(), df.indexKey) {
			df.indexKey = nil
			return true, nil
		}
		return false, nil
	}
}

// nextKV is a lower-level utility compared to nextKey. The differences are as follows:
// - It directly interacts with the KVIterator.
// - Returns true if the entire iterator/span is exhausted
// - Returns a kv pair instead of internally updating
func (df *DocumentFetcher) nextKV() (iterDone bool, kv *core.KeyValue, err error) {
	res, available := df.kvResultsIter.NextSync()
	if !available {
		return true, nil, nil
	}
	err = res.Error
	if err != nil {
		return true, nil, err
	}

	kv = &core.KeyValue{
		Key:   core.NewKey(res.Key),
		Value: res.Value,
	}
	return false, kv, nil
}

// processKV continuously processes the key value pairs we've received
// and step by step constructs the current encoded document
func (df *DocumentFetcher) processKV(kv *core.KeyValue) error {
	// skip MerkleCRDT meta-data priority key-value pair
	// implement here <--
	// instance := kv.Key.Name()
	// if instance != "v" {
	// 	return nil
	// }
	if df.doc == nil {
		return errors.New("Failed to process KV, uninitialized document object")
	}

	if df.indexKey == nil {
		// thihs is the first key for the document
		ik := df.ReadIndexKey(kv.Key)
		df.indexKey = ik.Bytes()
		df.doc.Reset()
		df.doc.Key = []byte(ik.BaseNamespace())
		// fmt.Println(df.doc.Key)
		// keyFD := df.schemaFields[0] // _key
		// df.doc.Properties[keyFD] = &document.EncProperty{
		// 	Raw: df.doc.Key[:],
		// }
	}

	// extract the FieldID and update the encoded doc properties map
	fieldID, err := kv.Key.FieldID()
	if err != nil {
		return err
	}
	fieldDesc, exists := df.schemaFields[fieldID]
	if !exists {
		return errors.New("Found field with no matching FieldDescription")
	}

	// @todo: Secondary Index might not have encoded FieldIDs
	// @body: Need to generalized the processKV, and overall Fetcher architecture
	// to better handle dynamic use cases beyond primary indexes. If a
	// secondary index is provided, we need to extract the indexed/implicit fields
	// from the KV pair.
	df.doc.Properties[fieldDesc] = &document.EncProperty{
		Desc: fieldDesc,
		Raw:  kv.Value,
	}
	// @todo: Extract Index implicit/stored keys
	return nil
}

// FetchNext returns a raw binary encoded document. It iterates over all the relevant
// keypairs from the underlying store and constructs the document.
func (df *DocumentFetcher) FetchNext(ctx context.Context) (*document.EncodedDocument, error) {
	if df.kvEnd {
		return nil, nil
	}

	if df.kv == nil {
		return nil, errors.New("Failed to get document, fetcher hasn't been initalized or started")
	}
	// save the DocKey of the current kv pair so we can track when we cross the doc pair boundries
	// keyparts := df.kv.Key.List()
	// key := keyparts[len(keyparts)-2]

	// iterate until we have collected all the necessary kv pairs for the doc
	// we'll know when were done when either
	// A) Reach the end of the iterator
	for {
		err := df.processKV(df.kv)
		if err != nil {
			return nil, err
		}

		end, err := df.nextKey(ctx)
		if err != nil {
			return nil, err
		}
		if end {
			return df.doc, nil
		}

		// // crossed document kv boundary?
		// // if so, return document
		// newkeyparts := df.kv.Key.List()
		// newKey := newkeyparts[len(newkeyparts)-2]
		// if newKey != key {
		// 	return df.doc, nil
		// }
	}
}

// FetchNextDecoded implements DocumentFetcher
func (df *DocumentFetcher) FetchNextDecoded(ctx context.Context) (*document.Document, error) {
	encdoc, err := df.FetchNext(ctx)
	if err != nil {
		return nil, err
	}
	if encdoc == nil {
		return nil, nil
	}

	df.decodedDoc, err = encdoc.Decode()
	if err != nil {
		return nil, err
	}

	return df.decodedDoc, nil
}

// FetchNextMap returns the next document as a map[string]interface{}
// The first return value is the parsed document key
func (df *DocumentFetcher) FetchNextMap(ctx context.Context) ([]byte, map[string]interface{}, error) {
	encdoc, err := df.FetchNext(ctx)
	if err != nil {
		return nil, nil, err
	}
	if encdoc == nil {
		return nil, nil, nil
	}

	doc, err := encdoc.DecodeToMap()
	if err != nil {
		return nil, nil, err
	}
	return encdoc.Key, doc, err
}

// ReadIndexKey extracts and returns the index key from the given KV key.
// @todo: Generalize ReadIndexKey to handle secondary indexes
func (df *DocumentFetcher) ReadIndexKey(key core.Key) core.Key {
	// currently were only support primary index keys
	// which have the following structure:
	// /db/data/<collection_id>/<index_id = 0>/<dockey>/<field_id>
	// We only care about the data up to /<dockey>
	// so were just going to do a quick hack
	return core.Key{Key: key.Parent()}
}

func (df *DocumentFetcher) Close() error {
	if df.kvIter == nil {
		return nil
	}

	err := df.kvIter.Close()
	if err != nil {
		return err
	}

	return df.kvResultsIter.Close()
}
