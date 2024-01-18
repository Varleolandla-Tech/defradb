// Copyright 2023 Democratized Data Foundation
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

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/datastore"
)

var _ client.DB = (*implicitTxnDB)(nil)
var _ client.DB = (*explicitTxnDB)(nil)
var _ client.Store = (*implicitTxnDB)(nil)
var _ client.Store = (*explicitTxnDB)(nil)

type implicitTxnDB struct {
	*db
}

type explicitTxnDB struct {
	*db
	txn          datastore.Txn
	lensRegistry client.LensRegistry
}

// ExecRequest executes a request against the database.
func (db *implicitTxnDB) ExecRequest(ctx context.Context, request string) *client.RequestResult {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		res := &client.RequestResult{}
		res.GQL.Errors = []error{err}
		return res
	}
	defer txn.Discard(ctx)

	res := db.execRequest(ctx, request, txn)
	if len(res.GQL.Errors) > 0 {
		return res
	}

	if err := txn.Commit(ctx); err != nil {
		res.GQL.Errors = []error{err}
		return res
	}

	return res
}

// ExecRequest executes a transaction request against the database.
func (db *explicitTxnDB) ExecRequest(
	ctx context.Context,
	request string,
) *client.RequestResult {
	return db.execRequest(ctx, request, db.txn)
}

// GetCollectionByName returns an existing collection within the database.
func (db *implicitTxnDB) GetCollectionByName(ctx context.Context, name string) (client.Collection, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getCollectionByName(ctx, txn, name)
}

// GetCollectionByName returns an existing collection within the database.
func (db *explicitTxnDB) GetCollectionByName(ctx context.Context, name string) (client.Collection, error) {
	return db.getCollectionByName(ctx, db.txn, name)
}

// GetCollectionsBySchemaRoot attempts to retrieve all collections using the given schema ID.
//
// If no matching collection is found an empty set will be returned.
func (db *implicitTxnDB) GetCollectionsBySchemaRoot(
	ctx context.Context,
	schemaRoot string,
) ([]client.Collection, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	cols, err := db.getCollectionsBySchemaRoot(ctx, txn, schemaRoot)
	if err != nil {
		return nil, err
	}

	return cols, nil
}

// GetCollectionsBySchemaRoot attempts to retrieve all collections using the given schema ID.
//
// If no matching collection is found an empty set will be returned.
func (db *explicitTxnDB) GetCollectionsBySchemaRoot(
	ctx context.Context,
	schemaRoot string,
) ([]client.Collection, error) {
	cols, err := db.getCollectionsBySchemaRoot(ctx, db.txn, schemaRoot)
	if err != nil {
		return nil, err
	}

	return cols, nil
}

// GetCollectionsByVersionID attempts to retrieve all collections using the given schema version ID.
//
// If no matching collections are found an empty set will be returned.
func (db *implicitTxnDB) GetCollectionsByVersionID(
	ctx context.Context, schemaVersionID string,
) ([]client.Collection, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	cols, err := db.getCollectionsByVersionID(ctx, txn, schemaVersionID)
	if err != nil {
		return nil, err
	}

	collections := make([]client.Collection, len(cols))
	for i, col := range cols {
		collections[i] = col
	}

	return collections, nil
}

// GetCollectionsByVersionID attempts to retrieve all collections using the given schema version ID.
//
// If no matching collections are found an empty set will be returned.
func (db *explicitTxnDB) GetCollectionsByVersionID(
	ctx context.Context, schemaVersionID string,
) ([]client.Collection, error) {
	cols, err := db.getCollectionsByVersionID(ctx, db.txn, schemaVersionID)
	if err != nil {
		return nil, err
	}

	collections := make([]client.Collection, len(cols))
	for i, col := range cols {
		collections[i] = col
	}

	return collections, nil
}

// GetAllCollections gets all the currently defined collections.
func (db *implicitTxnDB) GetAllCollections(ctx context.Context) ([]client.Collection, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getAllCollections(ctx, txn)
}

// GetAllCollections gets all the currently defined collections.
func (db *explicitTxnDB) GetAllCollections(ctx context.Context) ([]client.Collection, error) {
	return db.getAllCollections(ctx, db.txn)
}

// GetSchemasByName returns the all schema versions with the given name.
func (db *implicitTxnDB) GetSchemasByName(ctx context.Context, name string) ([]client.SchemaDescription, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getSchemasByName(ctx, txn, name)
}

// GetSchemasByName returns the all schema versions with the given name.
func (db *explicitTxnDB) GetSchemasByName(ctx context.Context, name string) ([]client.SchemaDescription, error) {
	return db.getSchemasByName(ctx, db.txn, name)
}

// GetSchemaByVersionID returns the schema description for the schema version of the
// ID provided.
//
// Will return an error if it is not found.
func (db *implicitTxnDB) GetSchemaByVersionID(ctx context.Context, versionID string) (client.SchemaDescription, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return client.SchemaDescription{}, err
	}
	defer txn.Discard(ctx)

	return db.getSchemaByVersionID(ctx, txn, versionID)
}

// GetSchemaByVersionID returns the schema description for the schema version of the
// ID provided.
//
// Will return an error if it is not found.
func (db *explicitTxnDB) GetSchemaByVersionID(ctx context.Context, versionID string) (client.SchemaDescription, error) {
	return db.getSchemaByVersionID(ctx, db.txn, versionID)
}

// GetSchemasByRoot returns the all schema versions for the given root.
func (db *implicitTxnDB) GetSchemasByRoot(ctx context.Context, root string) ([]client.SchemaDescription, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getSchemasByRoot(ctx, txn, root)
}

// GetSchemasByRoot returns the all schema versions for the given root.
func (db *explicitTxnDB) GetSchemasByRoot(ctx context.Context, root string) ([]client.SchemaDescription, error) {
	return db.getSchemasByRoot(ctx, db.txn, root)
}

// GetAllSchemas returns all schema versions that currently exist within
// this [Store].
func (db *implicitTxnDB) GetAllSchemas(ctx context.Context) ([]client.SchemaDescription, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getAllSchemas(ctx, txn)
}

// GetAllSchemas returns all schema versions that currently exist within
// this [Store].
func (db *explicitTxnDB) GetAllSchemas(ctx context.Context) ([]client.SchemaDescription, error) {
	return db.getAllSchemas(ctx, db.txn)
}

// GetAllIndexes gets all the indexes in the database.
func (db *implicitTxnDB) GetAllIndexes(
	ctx context.Context,
) (map[client.CollectionName][]client.IndexDescription, error) {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	return db.getAllIndexes(ctx, txn)
}

// GetAllIndexes gets all the indexes in the database.
func (db *explicitTxnDB) GetAllIndexes(
	ctx context.Context,
) (map[client.CollectionName][]client.IndexDescription, error) {
	return db.getAllIndexes(ctx, db.txn)
}

// AddSchema takes the provided GQL schema in SDL format, and applies it to the database,
// creating the necessary collections, request types, etc.
//
// All schema types provided must not exist prior to calling this, and they may not reference existing
// types previously defined.
func (db *implicitTxnDB) AddSchema(ctx context.Context, schemaString string) ([]client.CollectionDescription, error) {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	cols, err := db.addSchema(ctx, txn, schemaString)
	if err != nil {
		return nil, err
	}

	if err := txn.Commit(ctx); err != nil {
		return nil, err
	}
	return cols, nil
}

// AddSchema takes the provided GQL schema in SDL format, and applies it to the database,
// creating the necessary collections, request types, etc.
//
// All schema types provided must not exist prior to calling this, and they may not reference existing
// types previously defined.
func (db *explicitTxnDB) AddSchema(ctx context.Context, schemaString string) ([]client.CollectionDescription, error) {
	return db.addSchema(ctx, db.txn, schemaString)
}

// PatchSchema takes the given JSON patch string and applies it to the set of CollectionDescriptions
// present in the database.
//
// It will also update the GQL types used by the query system. It will error and not apply any of the
// requested, valid updates should the net result of the patch result in an invalid state.  The
// individual operations defined in the patch do not need to result in a valid state, only the net result
// of the full patch.
//
// The collections (including the schema version ID) will only be updated if any changes have actually
// been made, if the net result of the patch matches the current persisted description then no changes
// will be applied.
func (db *implicitTxnDB) PatchSchema(ctx context.Context, patchString string, setAsDefaultVersion bool) error {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = db.patchSchema(ctx, txn, patchString, setAsDefaultVersion)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// PatchSchema takes the given JSON patch string and applies it to the set of CollectionDescriptions
// present in the database.
//
// It will also update the GQL types used by the query system. It will error and not apply any of the
// requested, valid updates should the net result of the patch result in an invalid state.  The
// individual operations defined in the patch do not need to result in a valid state, only the net result
// of the full patch.
//
// The collections (including the schema version ID) will only be updated if any changes have actually
// been made, if the net result of the patch matches the current persisted description then no changes
// will be applied.
func (db *explicitTxnDB) PatchSchema(ctx context.Context, patchString string, setAsDefaultVersion bool) error {
	return db.patchSchema(ctx, db.txn, patchString, setAsDefaultVersion)
}

func (db *implicitTxnDB) SetDefaultSchemaVersion(ctx context.Context, schemaVersionID string) error {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = db.setDefaultSchemaVersion(ctx, txn, schemaVersionID)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

func (db *explicitTxnDB) SetDefaultSchemaVersion(ctx context.Context, schemaVersionID string) error {
	return db.setDefaultSchemaVersion(ctx, db.txn, schemaVersionID)
}

func (db *implicitTxnDB) SetMigration(ctx context.Context, cfg client.LensConfig) error {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = db.lensRegistry.SetMigration(ctx, cfg)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

func (db *explicitTxnDB) SetMigration(ctx context.Context, cfg client.LensConfig) error {
	return db.lensRegistry.SetMigration(ctx, cfg)
}

func (db *implicitTxnDB) AddView(ctx context.Context, query string, sdl string) ([]client.CollectionDefinition, error) {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return nil, err
	}
	defer txn.Discard(ctx)

	defs, err := db.addView(ctx, txn, query, sdl)
	if err != nil {
		return nil, err
	}

	err = txn.Commit(ctx)
	if err != nil {
		return nil, err
	}

	return defs, nil
}

func (db *explicitTxnDB) AddView(ctx context.Context, query string, sdl string) ([]client.CollectionDefinition, error) {
	return db.addView(ctx, db.txn, query, sdl)
}

// BasicImport imports a json dataset.
// filepath must be accessible to the node.
func (db *implicitTxnDB) BasicImport(ctx context.Context, filepath string) error {
	txn, err := db.NewTxn(ctx, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = db.basicImport(ctx, txn, filepath)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// BasicImport imports a json dataset.
// filepath must be accessible to the node.
func (db *explicitTxnDB) BasicImport(ctx context.Context, filepath string) error {
	return db.basicImport(ctx, db.txn, filepath)
}

// BasicExport exports the current data or subset of data to file in json format.
func (db *implicitTxnDB) BasicExport(ctx context.Context, config *client.BackupConfig) error {
	txn, err := db.NewTxn(ctx, true)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = db.basicExport(ctx, txn, config)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// BasicExport exports the current data or subset of data to file in json format.
func (db *explicitTxnDB) BasicExport(ctx context.Context, config *client.BackupConfig) error {
	return db.basicExport(ctx, db.txn, config)
}

// LensRegistry returns the LensRegistry in use by this database instance.
//
// It exposes several useful thread-safe migration related functions.
func (db *explicitTxnDB) LensRegistry() client.LensRegistry {
	return db.lensRegistry
}
