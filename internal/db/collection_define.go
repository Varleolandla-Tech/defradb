// Copyright 2024 Democratized Data Foundation
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
	"github.com/sourcenetwork/defradb/client/request"
	"github.com/sourcenetwork/defradb/internal/core"
	"github.com/sourcenetwork/defradb/internal/db/description"
)

func (db *db) createCollection(
	ctx context.Context,
	def client.CollectionDefinition,
	newDefinitions []client.CollectionDefinition,
) (client.Collection, error) {
	schema := def.Schema
	desc := def.Description
	txn := mustGetContextTxn(ctx)

	if desc.Name.HasValue() {
		exists, err := description.HasCollectionByName(ctx, txn, desc.Name.Value())
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrCollectionAlreadyExists
		}
	}

	existingDefinitions, err := db.getAllActiveDefinitions(ctx)
	if err != nil {
		return nil, err
	}

	schemaByName := map[string]client.SchemaDescription{}
	for _, existingDefinition := range existingDefinitions {
		schemaByName[existingDefinition.Schema.Name] = existingDefinition.Schema
	}
	for _, newDefinition := range newDefinitions {
		schemaByName[newDefinition.Schema.Name] = newDefinition.Schema
	}

	_, err = validateUpdateSchemaFields(schemaByName, client.SchemaDescription{}, schema)
	if err != nil {
		return nil, err
	}

	definitionsByName := map[string]client.CollectionDefinition{}
	for _, existingDefinition := range existingDefinitions {
		definitionsByName[existingDefinition.GetName()] = existingDefinition
	}
	for _, newDefinition := range newDefinitions {
		definitionsByName[newDefinition.GetName()] = newDefinition
	}
	err = db.validateNewCollection(def, definitionsByName)
	if err != nil {
		return nil, err
	}

	colSeq, err := db.getSequence(ctx, core.CollectionIDSequenceKey{})
	if err != nil {
		return nil, err
	}
	colID, err := colSeq.next(ctx)
	if err != nil {
		return nil, err
	}

	fieldSeq, err := db.getSequence(ctx, core.NewFieldIDSequenceKey(uint32(colID)))
	if err != nil {
		return nil, err
	}

	desc.ID = uint32(colID)
	desc.RootID = desc.ID

	schema, err = description.CreateSchemaVersion(ctx, txn, schema)
	if err != nil {
		return nil, err
	}
	desc.SchemaVersionID = schema.VersionID
	for _, localField := range desc.Fields {
		var fieldID uint64
		if localField.Name == request.DocIDFieldName {
			// There is no hard technical requirement for this, we just think it looks nicer
			// if the doc id is at the zero index.  It makes it look a little nicer in commit
			// queries too.
			fieldID = 0
		} else {
			fieldID, err = fieldSeq.next(ctx)
			if err != nil {
				return nil, err
			}
		}

		for i := range desc.Fields {
			if desc.Fields[i].Name == localField.Name {
				desc.Fields[i].ID = client.FieldID(fieldID)
				break
			}
		}
	}

	desc, err = description.SaveCollection(ctx, txn, desc)
	if err != nil {
		return nil, err
	}

	col := db.newCollection(desc, schema)

	for _, index := range desc.Indexes {
		if _, err := col.createIndex(ctx, index); err != nil {
			return nil, err
		}
	}

	return db.getCollectionByID(ctx, desc.ID)
}
