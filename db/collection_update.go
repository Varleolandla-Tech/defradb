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

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/sourcenetwork/immutable"
	"github.com/valyala/fastjson"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/events"
	"github.com/sourcenetwork/defradb/planner"
)

// UpdateWith updates a target document using the given updater type. Target
// can be a Filter statement, a single docKey, a single document,
// an array of docKeys, or an array of documents.
// If you want more type safety, use the respective typed versions of Update.
// Eg: UpdateWithFilter or UpdateWithKey
func (c *collection) UpdateWith(
	ctx context.Context,
	target any,
	updater string,
) (*client.UpdateResult, error) {
	switch t := target.(type) {
	case string, map[string]any, *request.Filter:
		return c.UpdateWithFilter(ctx, t, updater)
	case client.DocKey:
		return c.UpdateWithKey(ctx, t, updater)
	case []client.DocKey:
		return c.UpdateWithKeys(ctx, t, updater)
	default:
		return nil, client.ErrInvalidUpdateTarget
	}
}

// UpdateWithFilter updates using a filter to target documents for update.
// An updater value is provided, which could be a string Patch, string Merge Patch
// or a parsed Patch, or parsed Merge Patch.
func (c *collection) UpdateWithFilter(
	ctx context.Context,
	filter any,
	updater string,
) (*client.UpdateResult, error) {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return nil, err
	}
	defer c.discardImplicitTxn(ctx, txn)
	res, err := c.updateWithFilter(ctx, txn, filter, updater)
	if err != nil {
		return nil, err
	}
	return res, c.commitImplicitTxn(ctx, txn)
}

// UpdateWithKey updates using a DocKey to target a single document for update.
// An updater value is provided, which could be a string Patch, string Merge Patch
// or a parsed Patch, or parsed Merge Patch.
func (c *collection) UpdateWithKey(
	ctx context.Context,
	key client.DocKey,
	updater string,
) (*client.UpdateResult, error) {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return nil, err
	}
	defer c.discardImplicitTxn(ctx, txn)
	res, err := c.updateWithKey(ctx, txn, key, updater)
	if err != nil {
		return nil, err
	}

	return res, c.commitImplicitTxn(ctx, txn)
}

// UpdateWithKeys is the same as UpdateWithKey but accepts multiple keys as a slice.
// An updater value is provided, which could be a string Patch, string Merge Patch
// or a parsed Patch, or parsed Merge Patch.
func (c *collection) UpdateWithKeys(
	ctx context.Context,
	keys []client.DocKey,
	updater string,
) (*client.UpdateResult, error) {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return nil, err
	}
	defer c.discardImplicitTxn(ctx, txn)
	res, err := c.updateWithKeys(ctx, txn, keys, updater)
	if err != nil {
		return nil, err
	}

	return res, c.commitImplicitTxn(ctx, txn)
}

func (c *collection) updateWithKey(
	ctx context.Context,
	txn datastore.Txn,
	key client.DocKey,
	updater string,
) (*client.UpdateResult, error) {
	parsedUpdater, err := fastjson.Parse(updater)
	if err != nil {
		return nil, err
	}

	isPatch := false
	if parsedUpdater.Type() == fastjson.TypeArray {
		isPatch = true
	} else if parsedUpdater.Type() != fastjson.TypeObject {
		return nil, client.ErrInvalidUpdater
	}

	doc, err := c.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	v, err := doc.ToMap()
	if err != nil {
		return nil, err
	}

	if isPatch {
		// todo
	} else {
		err = c.applyMerge(ctx, txn, v, parsedUpdater.GetObject())
	}
	if err != nil {
		return nil, err
	}

	results := &client.UpdateResult{
		Count:   1,
		DocKeys: []string{key.String()},
	}
	return results, nil
}

func (c *collection) updateWithKeys(
	ctx context.Context,
	txn datastore.Txn,
	keys []client.DocKey,
	updater string,
) (*client.UpdateResult, error) {
	parsedUpdater, err := fastjson.Parse(updater)
	if err != nil {
		return nil, err
	}

	isPatch := false
	if parsedUpdater.Type() == fastjson.TypeArray {
		isPatch = true
	} else if parsedUpdater.Type() != fastjson.TypeObject {
		return nil, client.ErrInvalidUpdater
	}

	results := &client.UpdateResult{
		DocKeys: make([]string, len(keys)),
	}
	for i, key := range keys {
		doc, err := c.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		v, err := doc.ToMap()
		if err != nil {
			return nil, err
		}

		if isPatch {
			// todo
		} else {
			err = c.applyMerge(ctx, txn, v, parsedUpdater.GetObject())
		}
		if err != nil {
			return nil, err
		}

		results.DocKeys[i] = key.String()
		results.Count++
	}
	return results, nil
}

func (c *collection) updateWithFilter(
	ctx context.Context,
	txn datastore.Txn,
	filter any,
	updater string,
) (*client.UpdateResult, error) {
	parsedUpdater, err := fastjson.Parse(updater)
	if err != nil {
		return nil, err
	}

	isPatch := false
	isMerge := false
	switch parsedUpdater.Type() {
	case fastjson.TypeArray:
		isPatch = true
	case fastjson.TypeObject:
		isMerge = true
	default:
		return nil, client.ErrInvalidUpdater
	}

	// scan through docs with filter
	query, err := c.makeSelectionQuery(ctx, txn, filter)
	if err != nil {
		return nil, err
	}
	if err = query.Start(); err != nil {
		return nil, err
	}

	// If the query object isn't properly closed at any exit point log the error.
	defer func() {
		if err := query.Close(); err != nil {
			log.ErrorE(ctx, "Failed to close query after filter update", err)
		}
	}()

	results := &client.UpdateResult{
		DocKeys: make([]string, 0),
	}

	docMap := query.DocumentMap()

	// loop while we still have results from the filter query
	for {
		next, nextErr := query.Next()
		if nextErr != nil {
			return nil, err
		}
		// if theres no more records from the query, jump out of the loop
		if !next {
			break
		}

		// Get the document, and apply the patch
		doc := docMap.ToMap(query.Value())
		if isPatch {
			// todo
		} else if isMerge { // else is fine here
			err = c.applyMerge(ctx, txn, doc, parsedUpdater.GetObject())
		}
		if err != nil {
			return nil, err
		}

		// add successful updated doc to results
		results.DocKeys = append(results.DocKeys, doc[request.DocKeyFieldName].(string))
		results.Count++
	}

	return results, nil
}

func (c *collection) applyMerge(
	ctx context.Context,
	txn datastore.Txn,
	doc map[string]any,
	merge *fastjson.Object,
) error {
	keyStr, ok := doc["_key"].(string)
	if !ok {
		return ErrDocMissingKey
	}
	key := c.getPrimaryKey(keyStr)
	links := make([]core.DAGLink, 0)

	mergeMap := make(map[string]*fastjson.Value)
	merge.Visit(func(k []byte, v *fastjson.Value) {
		mergeMap[string(k)] = v
	})

	mergeCBOR := make(map[string]any)

	for mfield, mval := range mergeMap {
		if mval.Type() == fastjson.TypeObject {
			return ErrInvalidMergeValueType
		}

		fd, valid := c.desc.GetField(mfield)
		if !valid {
			return client.NewErrFieldNotExist(mfield)
		}

		if c.isFieldDescriptionRelationID(&fd) {
			return client.NewErrFieldNotExist(mfield)
		}

		cborVal, err := validateFieldSchema(mval, fd)
		if err != nil {
			return err
		}
		mergeCBOR[mfield] = cborVal

		val := client.NewCBORValue(fd.Typ, cborVal)
		fieldKey, fieldExists := c.tryGetFieldKey(key, mfield)
		if !fieldExists {
			return client.NewErrFieldNotExist(mfield)
		}

		c, _, err := c.saveDocValue(ctx, txn, fieldKey, val)
		if err != nil {
			return err
		}
		// links[mfield] = c
		links = append(links, core.DAGLink{
			Name: mfield,
			Cid:  c.Cid(),
		})
	}

	// Update CompositeDAG
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return err
	}
	buf, err := em.Marshal(mergeCBOR)
	if err != nil {
		return err
	}

	headNode, priority, err := c.saveValueToMerkleCRDT(
		ctx,
		txn,
		key.ToDataStoreKey(),
		client.COMPOSITE,
		buf,
		links,
	)
	if err != nil {
		return err
	}

	if c.db.events.Updates.HasValue() {
		txn.OnSuccess(
			func() {
				c.db.events.Updates.Value().Publish(
					events.Update{
						DocKey:   keyStr,
						Cid:      headNode.Cid(),
						SchemaID: c.schemaID,
						Block:    headNode,
						Priority: priority,
					},
				)
			},
		)
	}

	return nil
}

// validateFieldSchema takes a given value as an interface,
// and ensures it matches the supplied field description.
// It will do any minor parsing, like dates, and return
// the typed value again as an interface.
func validateFieldSchema(val *fastjson.Value, field client.FieldDescription) (any, error) {
	switch field.Kind {
	case client.FieldKind_DocKey, client.FieldKind_STRING:
		return getString(val)

	case client.FieldKind_STRING_ARRAY:
		return getArray(val, getString)

	case client.FieldKind_NILLABLE_STRING_ARRAY:
		return getNillableArray(val, getString)

	case client.FieldKind_BOOL:
		return getBool(val)

	case client.FieldKind_BOOL_ARRAY:
		return getArray(val, getBool)

	case client.FieldKind_NILLABLE_BOOL_ARRAY:
		return getNillableArray(val, getBool)

	case client.FieldKind_FLOAT, client.FieldKind_DECIMAL:
		return getFloat64(val)

	case client.FieldKind_FLOAT_ARRAY:
		return getArray(val, getFloat64)

	case client.FieldKind_NILLABLE_FLOAT_ARRAY:
		return getNillableArray(val, getFloat64)

	case client.FieldKind_DATETIME:
		// @TODO: Requires Typed Document refactor
		// to handle this correctly.
		// For now, we will persist DateTime as a
		// RFC3339 string
		// see https://github.com/sourcenetwork/defradb/issues/935
		return getString(val)

	case client.FieldKind_INT:
		return getInt64(val)

	case client.FieldKind_INT_ARRAY:
		return getArray(val, getInt64)

	case client.FieldKind_NILLABLE_INT_ARRAY:
		return getNillableArray(val, getInt64)

	case client.FieldKind_OBJECT, client.FieldKind_OBJECT_ARRAY,
		client.FieldKind_FOREIGN_OBJECT, client.FieldKind_FOREIGN_OBJECT_ARRAY:
		return nil, ErrMergeSubTypeNotSupported
	}

	return nil, client.NewErrUnhandledType("FieldKind", field.Kind)
}

func getString(v *fastjson.Value) (string, error) {
	b, err := v.StringBytes()
	return string(b), err
}

func getBool(v *fastjson.Value) (bool, error) {
	return v.Bool()
}

func getFloat64(v *fastjson.Value) (float64, error) {
	return v.Float64()
}

func getInt64(v *fastjson.Value) (int64, error) {
	return v.Int64()
}

func getArray[T any](
	val *fastjson.Value,
	typeGetter func(*fastjson.Value) (T, error),
) ([]T, error) {
	if val.Type() == fastjson.TypeNull {
		return nil, nil
	}

	valArray, err := val.Array()
	if err != nil {
		return nil, err
	}

	arr := make([]T, len(valArray))
	for i, arrItem := range valArray {
		if arrItem.Type() == fastjson.TypeNull {
			continue
		}
		arr[i], err = typeGetter(arrItem)
		if err != nil {
			return nil, err
		}
	}

	return arr, nil
}

func getNillableArray[T any](
	val *fastjson.Value,
	typeGetter func(*fastjson.Value) (T, error),
) ([]*T, error) {
	if val.Type() == fastjson.TypeNull {
		return nil, nil
	}

	valArray, err := val.Array()
	if err != nil {
		return nil, err
	}

	arr := make([]*T, len(valArray))
	for i, arrItem := range valArray {
		if arrItem.Type() == fastjson.TypeNull {
			continue
		}
		v, err := typeGetter(arrItem)
		if err != nil {
			return nil, err
		}
		arr[i] = &v
	}

	return arr, nil
}

// makeQuery constructs a simple query of the collection using the given filter.
// currently it doesn't support any other query operation other than filters.
// (IE: No limit, order, etc)
// Additionally it only queries for the root scalar fields of the object
func (c *collection) makeSelectionQuery(
	ctx context.Context,
	txn datastore.Txn,
	filter any,
) (planner.Query, error) {
	var f immutable.Option[request.Filter]
	var err error
	switch fval := filter.(type) {
	case string:
		if fval == "" {
			return nil, ErrInvalidFilter
		}

		f, err = c.db.parser.NewFilterFromString(c.Name(), fval)
		if err != nil {
			return nil, err
		}
	case immutable.Option[request.Filter]:
		f = fval
	default:
		return nil, ErrInvalidFilter
	}

	slct, err := c.makeSelectLocal(f)
	if err != nil {
		return nil, err
	}

	planner := planner.New(ctx, c.db, txn)
	return planner.MakePlan(&request.Request{
		Queries: []*request.OperationDefinition{
			{
				Selections: []request.Selection{
					slct,
				},
			},
		},
	})
}

func (c *collection) makeSelectLocal(filter immutable.Option[request.Filter]) (*request.Select, error) {
	slct := &request.Select{
		Field: request.Field{
			Name: c.Name(),
		},
		Filter: filter,
		Fields: make([]request.Selection, 0),
	}

	for _, fd := range c.Schema().Fields {
		if fd.IsObject() {
			continue
		}
		slct.Fields = append(slct.Fields, &request.Field{
			Name: fd.Name,
		})
	}

	return slct, nil
}
