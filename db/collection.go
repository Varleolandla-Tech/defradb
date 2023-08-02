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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/sourcenetwork/immutable"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"
	"github.com/sourcenetwork/defradb/core"
	ccid "github.com/sourcenetwork/defradb/core/cid"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/db/fetcher"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/events"
	"github.com/sourcenetwork/defradb/lens"
	"github.com/sourcenetwork/defradb/logging"
	"github.com/sourcenetwork/defradb/merkle/crdt"
)

var _ client.Collection = (*collection)(nil)

// collection stores data records at Documents, which are gathered
// together under a collection name. This is analogous to SQL Tables.
type collection struct {
	db *db

	// txn represents any externally provided [datastore.Txn] for which any
	// operation on this [collection] instance should be scoped to.
	//
	// If this has no value, operations requiring a transaction should use an
	// implicit internally managed transaction, which only lives for duration
	// of the operation in question.
	txn immutable.Option[datastore.Txn]

	colID uint32

	schemaID string

	desc client.CollectionDescription

	indexes        []CollectionIndex
	fetcherFactory func() fetcher.Fetcher
}

// @todo: Move the base Descriptions to an internal API within the db/ package.
// @body: Currently, the New/Create Collection APIs accept CollectionDescriptions
// as params. We want these Descriptions objects to be low level descriptions, and
// to be auto generated based on a more controllable and user friendly
// CollectionOptions object.

// NewCollection returns a pointer to a newly instanciated DB Collection
func (db *db) newCollection(desc client.CollectionDescription) (*collection, error) {
	if desc.Name == "" {
		return nil, client.NewErrUninitializeProperty("Collection", "Name")
	}

	if len(desc.Schema.Fields) == 0 {
		return nil, client.NewErrUninitializeProperty("Collection", "Fields")
	}

	docKeyField := desc.Schema.Fields[0]
	if docKeyField.Kind != client.FieldKind_DocKey || docKeyField.Name != request.KeyFieldName {
		return nil, ErrSchemaFirstFieldDocKey
	}

	for i, field := range desc.Schema.Fields {
		if field.Name == "" {
			return nil, client.NewErrUninitializeProperty("Collection.Schema", "Name")
		}
		if field.Kind == client.FieldKind_None {
			return nil, client.NewErrUninitializeProperty("Collection.Schema", "FieldKind")
		}
		if (field.Kind != client.FieldKind_DocKey && !field.IsObject()) &&
			field.Typ == client.NONE_CRDT {
			return nil, client.NewErrUninitializeProperty("Collection.Schema", "CRDT type")
		}
		desc.Schema.Fields[i].ID = client.FieldID(i)
	}

	return &collection{
		db: db,
		desc: client.CollectionDescription{
			ID:     desc.ID,
			Name:   desc.Name,
			Schema: desc.Schema,
		},
		colID: desc.ID,
	}, nil
}

// newFetcher returns a new fetcher instance for this collection.
// If a fetcherFactory is set, it will be used to create the fetcher.
// It's a very simple factory, but it allows us to inject a mock fetcher
// for testing.
func (c *collection) newFetcher() fetcher.Fetcher {
	var innerFetcher fetcher.Fetcher
	if c.fetcherFactory != nil {
		innerFetcher = c.fetcherFactory()
	} else {
		innerFetcher = new(fetcher.DocumentFetcher)
	}

	return lens.NewFetcher(innerFetcher, c.db.LensRegistry())
}

// createCollection creates a collection and saves it to the database in its system store.
// Note: Collection.ID is an autoincrementing value that is generated by the database.
func (db *db) createCollection(
	ctx context.Context,
	txn datastore.Txn,
	desc client.CollectionDescription,
) (client.Collection, error) {
	// check if collection by this name exists
	collectionKey := core.NewCollectionKey(desc.Name)
	exists, err := txn.Systemstore().Has(ctx, collectionKey.ToDS())
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrCollectionAlreadyExists
	}

	colSeq, err := db.getSequence(ctx, txn, core.COLLECTION)
	if err != nil {
		return nil, err
	}
	colID, err := colSeq.next(ctx, txn)
	if err != nil {
		return nil, err
	}
	desc.ID = uint32(colID)
	col, err := db.newCollection(desc)
	if err != nil {
		return nil, err
	}

	// Local elements such as secondary indexes should be excluded
	// from the (global) schemaId.
	globalSchemaBuf, err := json.Marshal(struct {
		Name   string
		Schema client.SchemaDescription
	}{col.desc.Name, col.desc.Schema})
	if err != nil {
		return nil, err
	}

	// add a reference to this DB by desc hash
	cid, err := ccid.NewSHA256CidV1(globalSchemaBuf)
	if err != nil {
		return nil, err
	}
	schemaID := cid.String()
	col.schemaID = schemaID

	// For new schemas the initial version id will match the schema id
	schemaVersionID := schemaID

	col.desc.Schema.VersionID = schemaVersionID
	col.desc.Schema.SchemaID = schemaID

	// buffer must include all the ids, as it is saved and loaded from the store later.
	buf, err := json.Marshal(col.desc)
	if err != nil {
		return nil, err
	}

	collectionSchemaVersionKey := core.NewCollectionSchemaVersionKey(schemaVersionID)
	// Whilst the schemaVersionKey is global, the data persisted at the key's location
	// is local to the node (the global only elements are not useful beyond key generation).
	err = txn.Systemstore().Put(ctx, collectionSchemaVersionKey.ToDS(), buf)
	if err != nil {
		return nil, err
	}

	collectionSchemaKey := core.NewCollectionSchemaKey(schemaID)
	err = txn.Systemstore().Put(ctx, collectionSchemaKey.ToDS(), []byte(schemaVersionID))
	if err != nil {
		return nil, err
	}

	err = txn.Systemstore().Put(ctx, collectionKey.ToDS(), []byte(schemaVersionID))
	if err != nil {
		return nil, err
	}

	log.Debug(
		ctx,
		"Created collection",
		logging.NewKV("Name", col.Name()),
		logging.NewKV("SchemaID", col.SchemaID()),
	)

	for _, index := range desc.Indexes {
		if _, err := col.createIndex(ctx, txn, index); err != nil {
			return nil, err
		}
	}
	return col, nil
}

// updateCollection updates the persisted collection description matching the name of the given
// description, to the values in the given description.
//
// It will validate the given description using [ValidateUpdateCollectionTxn] before updating it.
//
// The collection (including the schema version ID) will only be updated if any changes have actually
// been made, if the given description matches the current persisted description then no changes will be
// applied.
func (db *db) updateCollection(
	ctx context.Context,
	txn datastore.Txn,
	existingDescriptionsByName map[string]client.CollectionDescription,
	desc client.CollectionDescription,
) (client.Collection, error) {
	hasChanged, err := db.validateUpdateCollection(ctx, txn, existingDescriptionsByName, desc)
	if err != nil {
		return nil, err
	}

	if !hasChanged {
		return db.getCollectionByName(ctx, txn, desc.Name)
	}

	for i, field := range desc.Schema.Fields {
		if field.ID == client.FieldID(0) {
			// This is not wonderful and will probably break when we add the ability
			// to delete fields, however it is good enough for now and matches the
			// create behaviour.
			field.ID = client.FieldID(i)
			desc.Schema.Fields[i] = field
		}

		if field.Typ == client.NONE_CRDT {
			// If no CRDT Type has been provided, default to LWW_REGISTER.
			field.Typ = client.LWW_REGISTER
			desc.Schema.Fields[i] = field
		}
	}

	globalSchemaBuf, err := json.Marshal(desc.Schema)
	if err != nil {
		return nil, err
	}

	cid, err := ccid.NewSHA256CidV1(globalSchemaBuf)
	if err != nil {
		return nil, err
	}
	previousSchemaVersionID := desc.Schema.VersionID
	schemaVersionID := cid.String()
	desc.Schema.VersionID = schemaVersionID

	buf, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}

	collectionSchemaVersionKey := core.NewCollectionSchemaVersionKey(schemaVersionID)
	// Whilst the schemaVersionKey is global, the data persisted at the key's location
	// is local to the node (the global only elements are not useful beyond key generation).
	err = txn.Systemstore().Put(ctx, collectionSchemaVersionKey.ToDS(), buf)
	if err != nil {
		return nil, err
	}

	collectionSchemaKey := core.NewCollectionSchemaKey(desc.Schema.SchemaID)
	err = txn.Systemstore().Put(ctx, collectionSchemaKey.ToDS(), []byte(schemaVersionID))
	if err != nil {
		return nil, err
	}

	collectionKey := core.NewCollectionKey(desc.Name)
	err = txn.Systemstore().Put(ctx, collectionKey.ToDS(), []byte(schemaVersionID))
	if err != nil {
		return nil, err
	}

	schemaVersionHistoryKey := core.NewSchemaHistoryKey(desc.Schema.SchemaID, previousSchemaVersionID)
	err = txn.Systemstore().Put(ctx, schemaVersionHistoryKey.ToDS(), []byte(schemaVersionID))
	if err != nil {
		return nil, err
	}

	return db.getCollectionByName(ctx, txn, desc.Name)
}

// validateUpdateCollection validates that the given collection description is a valid update.
//
// Will return true if the given description differs from the current persisted state of the
// collection. Will return an error if it fails validation.
func (db *db) validateUpdateCollection(
	ctx context.Context,
	txn datastore.Txn,
	existingDescriptionsByName map[string]client.CollectionDescription,
	proposedDesc client.CollectionDescription,
) (bool, error) {
	if proposedDesc.Name == "" {
		return false, ErrCollectionNameEmpty
	}

	existingDesc, collectionExists := existingDescriptionsByName[proposedDesc.Name]
	if !collectionExists {
		return false, NewErrAddCollectionWithPatch(proposedDesc.Name)
	}

	if proposedDesc.ID != existingDesc.ID {
		return false, NewErrCollectionIDDoesntMatch(proposedDesc.Name, existingDesc.ID, proposedDesc.ID)
	}

	if proposedDesc.Schema.SchemaID != existingDesc.Schema.SchemaID {
		return false, NewErrSchemaIDDoesntMatch(
			proposedDesc.Name,
			existingDesc.Schema.SchemaID,
			proposedDesc.Schema.SchemaID,
		)
	}

	if proposedDesc.Schema.Name != existingDesc.Schema.Name {
		// There is actually little reason to not support this atm besides controlling the surface area
		// of the new feature.  Changing this should not break anything, but it should be tested first.
		return false, NewErrCannotModifySchemaName(existingDesc.Schema.Name, proposedDesc.Schema.Name)
	}

	if proposedDesc.Schema.VersionID != "" && proposedDesc.Schema.VersionID != existingDesc.Schema.VersionID {
		// If users specify this it will be overwritten, an error is prefered to quietly ignoring it.
		return false, ErrCannotSetVersionID
	}

	hasChangedFields, err := validateUpdateCollectionFields(existingDesc, proposedDesc)
	if err != nil {
		return hasChangedFields, err
	}

	hasChangedIndexes, err := validateUpdateCollectionIndexes(existingDesc.Indexes, proposedDesc.Indexes)
	return hasChangedFields || hasChangedIndexes, err
}

func validateUpdateCollectionFields(
	existingDesc client.CollectionDescription,
	proposedDesc client.CollectionDescription,
) (bool, error) {
	hasChanged := false
	existingFieldsByID := map[client.FieldID]client.FieldDescription{}
	existingFieldIndexesByName := map[string]int{}
	for i, field := range existingDesc.Schema.Fields {
		existingFieldIndexesByName[field.Name] = i
		existingFieldsByID[field.ID] = field
	}

	newFieldNames := map[string]struct{}{}
	newFieldIds := map[client.FieldID]struct{}{}
	for proposedIndex, proposedField := range proposedDesc.Schema.Fields {
		var existingField client.FieldDescription
		var fieldAlreadyExists bool
		if proposedField.ID != client.FieldID(0) ||
			proposedField.Name == request.KeyFieldName {
			existingField, fieldAlreadyExists = existingFieldsByID[proposedField.ID]
		}

		if proposedField.ID != client.FieldID(0) && !fieldAlreadyExists {
			return false, NewErrCannotSetFieldID(proposedField.Name, proposedField.ID)
		}

		// If the field is new, then the collection has changed
		hasChanged = hasChanged || !fieldAlreadyExists

		if !fieldAlreadyExists && (proposedField.Kind == client.FieldKind_FOREIGN_OBJECT ||
			proposedField.Kind == client.FieldKind_FOREIGN_OBJECT_ARRAY) {
			return false, NewErrCannotAddRelationalField(proposedField.Name, proposedField.Kind)
		}

		if _, isDuplicate := newFieldNames[proposedField.Name]; isDuplicate {
			return false, NewErrDuplicateField(proposedField.Name)
		}

		if fieldAlreadyExists && proposedField != existingField {
			return false, NewErrCannotMutateField(proposedField.ID, proposedField.Name)
		}

		if existingIndex := existingFieldIndexesByName[proposedField.Name]; fieldAlreadyExists &&
			proposedIndex != existingIndex {
			return false, NewErrCannotMoveField(proposedField.Name, proposedIndex, existingIndex)
		}

		if proposedField.Typ != client.NONE_CRDT && proposedField.Typ != client.LWW_REGISTER {
			return false, NewErrInvalidCRDTType(proposedField.Name, proposedField.Typ)
		}

		newFieldNames[proposedField.Name] = struct{}{}
		newFieldIds[proposedField.ID] = struct{}{}
	}

	for _, field := range existingDesc.Schema.Fields {
		if _, stillExists := newFieldIds[field.ID]; !stillExists {
			return false, NewErrCannotDeleteField(field.Name, field.ID)
		}
	}
	return hasChanged, nil
}

func validateUpdateCollectionIndexes(
	existingIndexes []client.IndexDescription,
	proposedIndexes []client.IndexDescription,
) (bool, error) {
	existingNameToIndex := map[string]client.IndexDescription{}
	for _, index := range existingIndexes {
		existingNameToIndex[index.Name] = index
	}
	for _, proposedIndex := range proposedIndexes {
		if existingIndex, exists := existingNameToIndex[proposedIndex.Name]; exists {
			if len(existingIndex.Fields) != len(proposedIndex.Fields) {
				return false, ErrCanNotChangeIndexWithPatch
			}
			for i := range existingIndex.Fields {
				if existingIndex.Fields[i] != proposedIndex.Fields[i] {
					return false, ErrCanNotChangeIndexWithPatch
				}
			}
			delete(existingNameToIndex, proposedIndex.Name)
		} else {
			return false, NewErrCannotAddIndexWithPatch(proposedIndex.Name)
		}
	}
	if len(existingNameToIndex) > 0 {
		for _, index := range existingNameToIndex {
			return false, NewErrCannotDropIndexWithPatch(index.Name)
		}
	}
	return false, nil
}

// getCollectionByVersionId returns the [*collection] at the given [schemaVersionId] version.
//
// Will return an error if the given key is empty, or not found.
func (db *db) getCollectionByVersionID(
	ctx context.Context,
	txn datastore.Txn,
	schemaVersionId string,
) (*collection, error) {
	if schemaVersionId == "" {
		return nil, ErrSchemaVersionIDEmpty
	}

	key := core.NewCollectionSchemaVersionKey(schemaVersionId)
	buf, err := txn.Systemstore().Get(ctx, key.ToDS())
	if err != nil {
		return nil, err
	}

	var desc client.CollectionDescription
	err = json.Unmarshal(buf, &desc)
	if err != nil {
		return nil, err
	}

	col := &collection{
		db:       db,
		desc:     desc,
		colID:    desc.ID,
		schemaID: desc.Schema.SchemaID,
	}

	err = col.loadIndexes(ctx, txn)
	if err != nil {
		return nil, err
	}

	return col, nil
}

// getCollectionByName returns an existing collection within the database.
func (db *db) getCollectionByName(ctx context.Context, txn datastore.Txn, name string) (client.Collection, error) {
	if name == "" {
		return nil, ErrCollectionNameEmpty
	}

	key := core.NewCollectionKey(name)
	buf, err := txn.Systemstore().Get(ctx, key.ToDS())
	if err != nil {
		return nil, err
	}

	schemaVersionId := string(buf)
	return db.getCollectionByVersionID(ctx, txn, schemaVersionId)
}

// getCollectionBySchemaID returns an existing collection using the schema hash ID.
func (db *db) getCollectionBySchemaID(
	ctx context.Context,
	txn datastore.Txn,
	schemaID string,
) (client.Collection, error) {
	if schemaID == "" {
		return nil, ErrSchemaIDEmpty
	}

	key := core.NewCollectionSchemaKey(schemaID)
	buf, err := txn.Systemstore().Get(ctx, key.ToDS())
	if err != nil {
		return nil, err
	}

	schemaVersionId := string(buf)
	return db.getCollectionByVersionID(ctx, txn, schemaVersionId)
}

// getAllCollections gets all the currently defined collections.
func (db *db) getAllCollections(ctx context.Context, txn datastore.Txn) ([]client.Collection, error) {
	// create collection system prefix query
	prefix := core.NewCollectionKey("")
	q, err := txn.Systemstore().Query(ctx, query.Query{
		Prefix: prefix.ToString(),
	})
	if err != nil {
		return nil, NewErrFailedToCreateCollectionQuery(err)
	}
	defer func() {
		if err := q.Close(); err != nil {
			log.ErrorE(ctx, "Failed to close collection query", err)
		}
	}()

	cols := make([]client.Collection, 0)
	for res := range q.Next() {
		if res.Error != nil {
			return nil, err
		}

		schemaVersionId := string(res.Value)
		col, err := db.getCollectionByVersionID(ctx, txn, schemaVersionId)
		if err != nil {
			return nil, NewErrFailedToGetCollection(schemaVersionId, err)
		}
		cols = append(cols, col)
	}

	return cols, nil
}

// GetAllDocKeys returns all the document keys that exist in the collection.
//
// @todo: We probably need a lock on the collection for this kind of op since
// it hits every key and will cause Tx conflicts for concurrent Txs
func (c *collection) GetAllDocKeys(ctx context.Context) (<-chan client.DocKeysResult, error) {
	txn, err := c.getTxn(ctx, true)
	if err != nil {
		return nil, err
	}

	return c.getAllDocKeysChan(ctx, txn)
}

func (c *collection) getAllDocKeysChan(
	ctx context.Context,
	txn datastore.Txn,
) (<-chan client.DocKeysResult, error) {
	prefix := core.PrimaryDataStoreKey{ // empty path for all keys prefix
		CollectionId: fmt.Sprint(c.colID),
	}
	q, err := txn.Datastore().Query(ctx, query.Query{
		Prefix:   prefix.ToString(),
		KeysOnly: true,
	})
	if err != nil {
		return nil, err
	}

	resCh := make(chan client.DocKeysResult)
	go func() {
		defer func() {
			if err := q.Close(); err != nil {
				log.ErrorE(ctx, "Failed to close AllDocKeys query", err)
			}
			close(resCh)
			c.discardImplicitTxn(ctx, txn)
		}()
		for res := range q.Next() {
			// check for Done on context first
			select {
			case <-ctx.Done():
				// we've been cancelled! ;)
				return
			default:
				// noop, just continue on the with the for loop
			}
			if res.Error != nil {
				resCh <- client.DocKeysResult{
					Err: res.Error,
				}
				return
			}

			// now we have a doc key
			rawDocKey := ds.NewKey(res.Key).BaseNamespace()
			key, err := client.NewDocKeyFromString(rawDocKey)
			if err != nil {
				resCh <- client.DocKeysResult{
					Err: res.Error,
				}
				return
			}
			resCh <- client.DocKeysResult{
				Key: key,
			}
		}
	}()

	return resCh, nil
}

// Description returns the client.CollectionDescription.
func (c *collection) Description() client.CollectionDescription {
	return c.desc
}

// Name returns the collection name.
func (c *collection) Name() string {
	return c.desc.Name
}

// Schema returns the Schema of the collection.
func (c *collection) Schema() client.SchemaDescription {
	return c.desc.Schema
}

// ID returns the ID of the collection.
func (c *collection) ID() uint32 {
	return c.colID
}

func (c *collection) SchemaID() string {
	return c.schemaID
}

// WithTxn returns a new instance of the collection, with a transaction
// handle instead of a raw DB handle.
func (c *collection) WithTxn(txn datastore.Txn) client.Collection {
	return &collection{
		db:             c.db,
		txn:            immutable.Some(txn),
		desc:           c.desc,
		colID:          c.colID,
		schemaID:       c.schemaID,
		indexes:        c.indexes,
		fetcherFactory: c.fetcherFactory,
	}
}

// Create a new document.
// Will verify the DocKey/CID to ensure that the new document is correctly formatted.
func (c *collection) Create(ctx context.Context, doc *client.Document) error {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return err
	}
	defer c.discardImplicitTxn(ctx, txn)

	err = c.create(ctx, txn, doc)
	if err != nil {
		return err
	}
	return c.commitImplicitTxn(ctx, txn)
}

// CreateMany creates a collection of documents at once.
// Will verify the DocKey/CID to ensure that the new documents are correctly formatted.
func (c *collection) CreateMany(ctx context.Context, docs []*client.Document) error {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return err
	}
	defer c.discardImplicitTxn(ctx, txn)

	for _, doc := range docs {
		err = c.create(ctx, txn, doc)
		if err != nil {
			return err
		}
	}
	return c.commitImplicitTxn(ctx, txn)
}

func (c *collection) getKeysFromDoc(
	doc *client.Document,
) (client.DocKey, core.PrimaryDataStoreKey, error) {
	docKey, err := doc.GenerateDocKey()
	if err != nil {
		return client.DocKey{}, core.PrimaryDataStoreKey{}, err
	}

	primaryKey := c.getPrimaryKeyFromDocKey(docKey)
	if primaryKey.DocKey != doc.Key().String() {
		return client.DocKey{}, core.PrimaryDataStoreKey{},
			NewErrDocVerification(doc.Key().String(), primaryKey.DocKey)
	}
	return docKey, primaryKey, nil
}

func (c *collection) create(ctx context.Context, txn datastore.Txn, doc *client.Document) error {
	// This has to be done before dockey verification happens in the next step.
	if err := doc.RemapAliasFieldsAndDockey(c.desc.Schema.Fields); err != nil {
		return err
	}

	dockey, primaryKey, err := c.getKeysFromDoc(doc)
	if err != nil {
		return err
	}

	// check if doc already exists
	exists, isDeleted, err := c.exists(ctx, txn, primaryKey)
	if err != nil {
		return err
	}
	if exists {
		return NewErrDocumentAlreadyExists(primaryKey.DocKey)
	}
	if isDeleted {
		return NewErrDocumentDeleted(primaryKey.DocKey)
	}

	// write value object marker if we have an empty doc
	if len(doc.Values()) == 0 {
		valueKey := c.getDSKeyFromDockey(dockey)
		err = txn.Datastore().Put(ctx, valueKey.ToDS(), []byte{base.ObjectMarker})
		if err != nil {
			return err
		}
	}

	// write data to DB via MerkleClock/CRDT
	_, err = c.save(ctx, txn, doc, true)
	if err != nil {
		return err
	}

	return c.indexNewDoc(ctx, txn, doc)
}

// Update an existing document with the new values.
// Any field that needs to be removed or cleared should call doc.Clear(field) before.
// Any field that is nil/empty that hasn't called Clear will be ignored.
func (c *collection) Update(ctx context.Context, doc *client.Document) error {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return err
	}
	defer c.discardImplicitTxn(ctx, txn)

	primaryKey := c.getPrimaryKeyFromDocKey(doc.Key())
	exists, isDeleted, err := c.exists(ctx, txn, primaryKey)
	if err != nil {
		return err
	}
	if !exists {
		return client.ErrDocumentNotFound
	}
	if isDeleted {
		return NewErrDocumentDeleted(primaryKey.DocKey)
	}

	err = c.update(ctx, txn, doc)
	if err != nil {
		return err
	}

	return c.commitImplicitTxn(ctx, txn)
}

// Contract: DB Exists check is already performed, and a doc with the given key exists.
// Note: Should we CompareAndSet the update, IE: Query(read-only) the state, and update if changed
// or, just update everything regardless.
// Should probably be smart about the update due to the MerkleCRDT overhead, shouldn't
// add to the bloat.
func (c *collection) update(ctx context.Context, txn datastore.Txn, doc *client.Document) error {
	_, err := c.save(ctx, txn, doc, false)
	if err != nil {
		return err
	}
	return nil
}

// Save a document into the db.
// Either by creating a new document or by updating an existing one
func (c *collection) Save(ctx context.Context, doc *client.Document) error {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return err
	}
	defer c.discardImplicitTxn(ctx, txn)

	// Check if document already exists with key
	primaryKey := c.getPrimaryKeyFromDocKey(doc.Key())
	exists, isDeleted, err := c.exists(ctx, txn, primaryKey)
	if err != nil {
		return err
	}

	if !isDeleted {
		if exists {
			err = c.update(ctx, txn, doc)
		} else {
			err = c.create(ctx, txn, doc)
		}
		if err != nil {
			return err
		}
	}
	return c.commitImplicitTxn(ctx, txn)
}

func (c *collection) save(
	ctx context.Context,
	txn datastore.Txn,
	doc *client.Document,
	isCreate bool,
) (cid.Cid, error) {
	if !isCreate {
		err := c.updateIndexedDoc(ctx, txn, doc)
		if err != nil {
			return cid.Undef, err
		}
	}
	// NOTE: We delay the final Clean() call until we know
	// the commit on the transaction is successful. If we didn't
	// wait, and just did it here, then *if* the commit fails down
	// the line, then we have no way to roll back the state
	// side-effect on the document func called here.
	txn.OnSuccess(func() {
		doc.Clean()
	})

	// New batch transaction/store (optional/todo)
	// Ensute/Set doc object marker
	// Loop through doc values
	//	=> 		instantiate MerkleCRDT objects
	//	=> 		Set/Publish new CRDT values
	primaryKey := c.getPrimaryKeyFromDocKey(doc.Key())
	links := make([]core.DAGLink, 0)
	docProperties := make(map[string]any)
	for k, v := range doc.Fields() {
		val, err := doc.GetValueWithField(v)
		if err != nil {
			return cid.Undef, err
		}

		if val.IsDirty() {
			fieldKey, fieldExists := c.tryGetFieldKey(primaryKey, k)

			if !fieldExists {
				return cid.Undef, client.NewErrFieldNotExist(k)
			}

			fieldDescription, valid := c.desc.Schema.GetField(k)
			if !valid {
				return cid.Undef, client.NewErrFieldNotExist(k)
			}

			relationFieldDescription, isSecondaryRelationID := c.isSecondaryIDField(fieldDescription)
			if isSecondaryRelationID {
				primaryId := val.Value().(string)

				err = c.patchPrimaryDoc(ctx, txn, relationFieldDescription, primaryKey.DocKey, primaryId)
				if err != nil {
					return cid.Undef, err
				}

				// If this field was a secondary relation ID the related document will have been
				// updated instead and we should discard this value
				continue
			}

			node, _, err := c.saveDocValue(ctx, txn, fieldKey, val)
			if err != nil {
				return cid.Undef, err
			}
			if val.IsDelete() {
				docProperties[k] = nil
			} else {
				docProperties[k] = val.Value()
			}

			link := core.DAGLink{
				Name: k,
				Cid:  node.Cid(),
			}
			links = append(links, link)
		}
	}
	// Update CompositeDAG
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return cid.Undef, err
	}
	buf, err := em.Marshal(docProperties)
	if err != nil {
		return cid.Undef, nil
	}

	headNode, priority, err := c.saveValueToMerkleCRDT(
		ctx,
		txn,
		primaryKey.ToDataStoreKey(),
		client.COMPOSITE,
		buf,
		links,
		client.Active,
	)
	if err != nil {
		return cid.Undef, err
	}

	if c.db.events.Updates.HasValue() {
		txn.OnSuccess(
			func() {
				c.db.events.Updates.Value().Publish(
					events.Update{
						DocKey:   doc.Key().String(),
						Cid:      headNode.Cid(),
						SchemaID: c.schemaID,
						Block:    headNode,
						Priority: priority,
					},
				)
			},
		)
	}

	txn.OnSuccess(func() {
		doc.SetHead(headNode.Cid())
	})

	return headNode.Cid(), nil
}

// Delete will attempt to delete a document by key will return true if a deletion is successful,
// and return false, along with an error, if it cannot.
// If the document doesn't exist, then it will return false, and a ErrDocumentNotFound error.
// This operation will all state relating to the given DocKey. This includes data, block, and head storage.
func (c *collection) Delete(ctx context.Context, key client.DocKey) (bool, error) {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return false, err
	}
	defer c.discardImplicitTxn(ctx, txn)

	primaryKey := c.getPrimaryKeyFromDocKey(key)
	exists, isDeleted, err := c.exists(ctx, txn, primaryKey)
	if err != nil {
		return false, err
	}
	if !exists || isDeleted {
		return false, client.ErrDocumentNotFound
	}
	if isDeleted {
		return false, NewErrDocumentDeleted(primaryKey.DocKey)
	}

	err = c.applyDelete(ctx, txn, primaryKey)
	if err != nil {
		return false, err
	}
	return true, c.commitImplicitTxn(ctx, txn)
}

// Exists checks if a given document exists with supplied DocKey.
func (c *collection) Exists(ctx context.Context, key client.DocKey) (bool, error) {
	txn, err := c.getTxn(ctx, false)
	if err != nil {
		return false, err
	}
	defer c.discardImplicitTxn(ctx, txn)

	primaryKey := c.getPrimaryKeyFromDocKey(key)
	exists, isDeleted, err := c.exists(ctx, txn, primaryKey)
	if err != nil && !errors.Is(err, ds.ErrNotFound) {
		return false, err
	}
	return exists && !isDeleted, c.commitImplicitTxn(ctx, txn)
}

// check if a document exists with the given key
func (c *collection) exists(
	ctx context.Context,
	txn datastore.Txn,
	key core.PrimaryDataStoreKey,
) (exists bool, isDeleted bool, err error) {
	val, err := txn.Datastore().Get(ctx, key.ToDS())
	if err != nil && errors.Is(err, ds.ErrNotFound) {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	if bytes.Equal(val, []byte{base.DeletedObjectMarker}) {
		return true, true, nil
	}

	return true, false, nil
}

func (c *collection) saveDocValue(
	ctx context.Context,
	txn datastore.Txn,
	key core.DataStoreKey,
	val client.Value,
) (ipld.Node, uint64, error) {
	switch val.Type() {
	case client.LWW_REGISTER:
		wval, ok := val.(client.WriteableValue)
		if !ok {
			return nil, 0, client.ErrValueTypeMismatch
		}
		var bytes []byte
		var err error
		if val.IsDelete() { // empty byte array
			bytes = []byte{}
		} else {
			bytes, err = wval.Bytes()
			if err != nil {
				return nil, 0, err
			}
		}
		return c.saveValueToMerkleCRDT(ctx, txn, key, client.LWW_REGISTER, bytes)
	default:
		return nil, 0, ErrUnknownCRDT
	}
}

func (c *collection) saveValueToMerkleCRDT(
	ctx context.Context,
	txn datastore.Txn,
	key core.DataStoreKey,
	ctype client.CType,
	args ...any) (ipld.Node, uint64, error) {
	switch ctype {
	case client.LWW_REGISTER:
		fieldID, err := strconv.Atoi(key.FieldId)
		if err != nil {
			return nil, 0, err
		}
		field, _ := c.Description().GetFieldByID(client.FieldID(fieldID))
		merkleCRDT, err := c.db.crdtFactory.InstanceWithStores(
			txn,
			core.NewCollectionSchemaVersionKey(c.Schema().VersionID),
			c.db.events.Updates,
			ctype,
			key,
			field.Name,
		)
		if err != nil {
			return nil, 0, err
		}

		var bytes []byte
		var ok bool
		// parse args
		if len(args) != 1 {
			return nil, 0, ErrUnknownCRDTArgument
		}
		bytes, ok = args[0].([]byte)
		if !ok {
			return nil, 0, ErrUnknownCRDTArgument
		}
		lwwreg := merkleCRDT.(*crdt.MerkleLWWRegister)
		return lwwreg.Set(ctx, bytes)
	case client.COMPOSITE:
		key = key.WithFieldId(core.COMPOSITE_NAMESPACE)
		merkleCRDT, err := c.db.crdtFactory.InstanceWithStores(
			txn,
			core.NewCollectionSchemaVersionKey(c.Schema().VersionID),
			c.db.events.Updates,
			ctype,
			key,
			"",
		)
		if err != nil {
			return nil, 0, err
		}

		// parse args
		if len(args) < 2 {
			return nil, 0, ErrUnknownCRDTArgument
		}
		bytes, ok := args[0].([]byte)
		if !ok {
			return nil, 0, ErrUnknownCRDTArgument
		}
		links, ok := args[1].([]core.DAGLink)
		if !ok {
			return nil, 0, ErrUnknownCRDTArgument
		}
		comp := merkleCRDT.(*crdt.MerkleCompositeDAG)
		if len(args) > 2 {
			status, ok := args[2].(client.DocumentStatus)
			if !ok {
				return nil, 0, ErrUnknownCRDTArgument
			}
			if status.IsDeleted() {
				return comp.Delete(ctx, links)
			}
		}
		return comp.Set(ctx, bytes, links)
	}
	return nil, 0, ErrUnknownCRDT
}

// getTxn gets or creates a new transaction from the underlying db.
// If the collection already has a txn, return the existing one.
// Otherwise, create a new implicit transaction.
func (c *collection) getTxn(ctx context.Context, readonly bool) (datastore.Txn, error) {
	if c.txn.HasValue() {
		return c.txn.Value(), nil
	}
	return c.db.NewTxn(ctx, readonly)
}

// discardImplicitTxn is a proxy function used by the collection to execute the Discard()
// transaction function only if its an implicit transaction.
//
// Implicit transactions are transactions that are created *during* an operation execution as a side effect.
//
// Explicit transactions are provided to the collection object via the "WithTxn(...)" function.
func (c *collection) discardImplicitTxn(ctx context.Context, txn datastore.Txn) {
	if !c.txn.HasValue() {
		txn.Discard(ctx)
	}
}

func (c *collection) commitImplicitTxn(ctx context.Context, txn datastore.Txn) error {
	if !c.txn.HasValue() {
		return txn.Commit(ctx)
	}
	return nil
}

func (c *collection) getPrimaryKey(docKey string) core.PrimaryDataStoreKey {
	return core.PrimaryDataStoreKey{
		CollectionId: fmt.Sprint(c.colID),
		DocKey:       docKey,
	}
}

func (c *collection) getPrimaryKeyFromDocKey(docKey client.DocKey) core.PrimaryDataStoreKey {
	return core.PrimaryDataStoreKey{
		CollectionId: fmt.Sprint(c.colID),
		DocKey:       docKey.String(),
	}
}

func (c *collection) getDSKeyFromDockey(docKey client.DocKey) core.DataStoreKey {
	return core.DataStoreKey{
		CollectionID: fmt.Sprint(c.colID),
		DocKey:       docKey.String(),
		InstanceType: core.ValueKey,
	}
}

func (c *collection) tryGetFieldKey(key core.PrimaryDataStoreKey, fieldName string) (core.DataStoreKey, bool) {
	fieldId, hasField := c.tryGetSchemaFieldID(fieldName)
	if !hasField {
		return core.DataStoreKey{}, false
	}

	return core.DataStoreKey{
		CollectionID: key.CollectionId,
		DocKey:       key.DocKey,
		FieldId:      strconv.FormatUint(uint64(fieldId), 10),
	}, true
}

// tryGetSchemaFieldID returns the FieldID of the given fieldName.
// Will return false if the field is not found.
func (c *collection) tryGetSchemaFieldID(fieldName string) (uint32, bool) {
	for _, field := range c.desc.Schema.Fields {
		if field.Name == fieldName {
			if field.IsObject() || field.IsObjectArray() {
				// We do not wish to match navigational properties, only
				// fields directly on the collection.
				return uint32(0), false
			}
			return uint32(field.ID), true
		}
	}

	return uint32(0), false
}
