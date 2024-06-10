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
	"reflect"
	"strconv"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/lens-vm/lens/host-go/config/model"
	"github.com/sourcenetwork/immutable"

	"github.com/sourcenetwork/defradb/acp"
	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"
	"github.com/sourcenetwork/defradb/errors"
	"github.com/sourcenetwork/defradb/events"
	"github.com/sourcenetwork/defradb/internal/core"
	coreblock "github.com/sourcenetwork/defradb/internal/core/block"
	"github.com/sourcenetwork/defradb/internal/db/base"
	"github.com/sourcenetwork/defradb/internal/db/description"
	"github.com/sourcenetwork/defradb/internal/db/fetcher"
	"github.com/sourcenetwork/defradb/internal/lens"
	merklecrdt "github.com/sourcenetwork/defradb/internal/merkle/crdt"
)

var _ client.Collection = (*collection)(nil)

// collection stores data records at Documents, which are gathered
// together under a collection name. This is analogous to SQL Tables.
type collection struct {
	db             *db
	def            client.CollectionDefinition
	indexes        []CollectionIndex
	fetcherFactory func() fetcher.Fetcher
}

// @todo: Move the base Descriptions to an internal API within the db/ package.
// @body: Currently, the New/Create Collection APIs accept CollectionDescriptions
// as params. We want these Descriptions objects to be low level descriptions, and
// to be auto generated based on a more controllable and user friendly
// CollectionOptions object.

// newCollection returns a pointer to a newly instantiated DB Collection
func (db *db) newCollection(desc client.CollectionDescription, schema client.SchemaDescription) *collection {
	return &collection{
		db:  db,
		def: client.CollectionDefinition{Description: desc, Schema: schema},
	}
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

// validateCollectionDefinitionPolicyDesc validates that the policy definition is valid, beyond syntax.
//
// Ensures that the information within the policy definition makes sense,
// this function might also make relevant remote calls using the acp system.
func (db *db) validateCollectionDefinitionPolicyDesc(
	ctx context.Context,
	policyDesc immutable.Option[client.PolicyDescription],
) error {
	if !policyDesc.HasValue() {
		// No policy validation needed, whether acp exists or not doesn't matter.
		return nil
	}

	// If there is a policy specified, but the database does not have
	// acp enabled/available return an error, database must have an acp available
	// to enable access control (inorder to adhere to the policy specified).
	if !db.acp.HasValue() {
		return ErrCanNotHavePolicyWithoutACP
	}

	// If we have the policy specified on the collection, and acp is available/enabled,
	// then using the acp system we need to ensure the policy id specified
	// actually exists as a policy, and the resource name exists on that policy
	// and that the resource is a valid DPI.
	return db.acp.Value().ValidateResourceExistsOnValidDPI(
		ctx,
		policyDesc.Value().ID,
		policyDesc.Value().ResourceName,
	)
}

// updateSchema updates the persisted schema description matching the name of the given
// description, to the values in the given description.
//
// It will validate the given description using [validateUpdateSchema] before updating it.
//
// The schema (including the schema version ID) will only be updated if any changes have actually
// been made, if the given description matches the current persisted description then no changes will be
// applied.
func (db *db) updateSchema(
	ctx context.Context,
	existingSchemaByName map[string]client.SchemaDescription,
	proposedDescriptionsByName map[string]client.SchemaDescription,
	schema client.SchemaDescription,
	migration immutable.Option[model.Lens],
	setAsActiveVersion bool,
) error {
	hasChanged, err := db.validateUpdateSchema(
		existingSchemaByName,
		proposedDescriptionsByName,
		schema,
	)
	if err != nil {
		return err
	}

	if !hasChanged {
		return nil
	}

	for _, field := range schema.Fields {
		if field.Kind.IsObject() && !field.Kind.IsArray() {
			idFieldName := field.Name + "_id"
			if _, ok := schema.GetFieldByName(idFieldName); !ok {
				schema.Fields = append(schema.Fields, client.SchemaFieldDescription{
					Name: idFieldName,
					Kind: client.FieldKind_DocID,
				})
			}
		}
	}

	for i, field := range schema.Fields {
		if field.Typ == client.NONE_CRDT {
			// If no CRDT Type has been provided, default to LWW_REGISTER.
			field.Typ = client.LWW_REGISTER
			schema.Fields[i] = field
		}
	}

	txn := mustGetContextTxn(ctx)
	previousVersionID := schema.VersionID
	schema, err = description.CreateSchemaVersion(ctx, txn, schema)
	if err != nil {
		return err
	}

	// After creating the new schema version, we need to create new collection versions for
	// any collection using the previous version.  These will be inactive unless [setAsActiveVersion]
	// is true.

	cols, err := description.GetCollectionsBySchemaVersionID(ctx, txn, previousVersionID)
	if err != nil {
		return err
	}

	colSeq, err := db.getSequence(ctx, core.CollectionIDSequenceKey{})
	if err != nil {
		return err
	}

	for _, col := range cols {
		previousID := col.ID

		existingCols, err := description.GetCollectionsBySchemaVersionID(ctx, txn, schema.VersionID)
		if err != nil {
			return err
		}

		// The collection version may exist before the schema version was created locally.  This is
		// because migrations for the globally known schema version may have been registered locally
		// (typically to handle documents synced over P2P at higher versions) before the local schema
		// was updated.  We need to check for them now, and update them instead of creating new ones
		// if they exist.
		var isExistingCol bool
	existingColLoop:
		for _, existingCol := range existingCols {
			sources := existingCol.CollectionSources()
			for _, source := range sources {
				// Make sure that this collection is the parent of the current [col], and not part of
				// another collection set that happens to be using the same schema.
				if source.SourceCollectionID == previousID {
					if existingCol.RootID == client.OrphanRootID {
						existingCol.RootID = col.RootID
					}

					fieldSeq, err := db.getSequence(ctx, core.NewFieldIDSequenceKey(existingCol.RootID))
					if err != nil {
						return err
					}

					for _, globalField := range schema.Fields {
						var fieldID client.FieldID
						// We must check the source collection if the field already exists, and take its ID
						// from there, otherwise the field must be generated by the sequence.
						existingField, ok := col.GetFieldByName(globalField.Name)
						if ok {
							fieldID = existingField.ID
						} else {
							nextFieldID, err := fieldSeq.next(ctx)
							if err != nil {
								return err
							}
							fieldID = client.FieldID(nextFieldID)
						}

						existingCol.Fields = append(
							existingCol.Fields,
							client.CollectionFieldDescription{
								Name: globalField.Name,
								ID:   fieldID,
							},
						)
					}
					existingCol, err = description.SaveCollection(ctx, txn, existingCol)
					if err != nil {
						return err
					}
					isExistingCol = true
					break existingColLoop
				}
			}
		}

		if !isExistingCol {
			colID, err := colSeq.next(ctx)
			if err != nil {
				return err
			}

			fieldSeq, err := db.getSequence(ctx, core.NewFieldIDSequenceKey(col.RootID))
			if err != nil {
				return err
			}

			// Create any new collections without a name (inactive), if [setAsActiveVersion] is true
			// they will be activated later along with any existing collection versions.
			col.Name = immutable.None[string]()
			col.ID = uint32(colID)
			col.SchemaVersionID = schema.VersionID
			col.Sources = []any{
				&client.CollectionSource{
					SourceCollectionID: previousID,
					Transform:          migration,
				},
			}

			for _, globalField := range schema.Fields {
				_, exists := col.GetFieldByName(globalField.Name)
				if !exists {
					fieldID, err := fieldSeq.next(ctx)
					if err != nil {
						return err
					}

					col.Fields = append(
						col.Fields,
						client.CollectionFieldDescription{
							Name: globalField.Name,
							ID:   client.FieldID(fieldID),
						},
					)
				}
			}

			_, err = description.SaveCollection(ctx, txn, col)
			if err != nil {
				return err
			}

			if migration.HasValue() {
				err = db.LensRegistry().SetMigration(ctx, col.ID, migration.Value())
				if err != nil {
					return err
				}
			}
		}
	}

	if setAsActiveVersion {
		// activate collection versions using the new schema ID.  This call must be made after
		// all new collection versions have been saved.
		err = db.setActiveSchemaVersion(ctx, schema.VersionID)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateUpdateSchema validates that the given schema description is a valid update.
//
// Will return true if the given description differs from the current persisted state of the
// schema. Will return an error if it fails validation.
func (db *db) validateUpdateSchema(
	existingDescriptionsByName map[string]client.SchemaDescription,
	proposedDescriptionsByName map[string]client.SchemaDescription,
	proposedDesc client.SchemaDescription,
) (bool, error) {
	if proposedDesc.Name == "" {
		return false, ErrSchemaNameEmpty
	}

	existingDesc, collectionExists := existingDescriptionsByName[proposedDesc.Name]
	if !collectionExists {
		return false, NewErrAddCollectionWithPatch(proposedDesc.Name)
	}

	if proposedDesc.Root != existingDesc.Root {
		return false, NewErrSchemaRootDoesntMatch(
			proposedDesc.Name,
			existingDesc.Root,
			proposedDesc.Root,
		)
	}

	if proposedDesc.Name != existingDesc.Name {
		// There is actually little reason to not support this atm besides controlling the surface area
		// of the new feature.  Changing this should not break anything, but it should be tested first.
		return false, NewErrCannotModifySchemaName(existingDesc.Name, proposedDesc.Name)
	}

	if proposedDesc.VersionID != "" && proposedDesc.VersionID != existingDesc.VersionID {
		// If users specify this it will be overwritten, an error is preferred to quietly ignoring it.
		return false, ErrCannotSetVersionID
	}

	hasChangedFields, err := validateUpdateSchemaFields(proposedDescriptionsByName, existingDesc, proposedDesc)
	if err != nil {
		return hasChangedFields, err
	}

	return hasChangedFields, err
}

func validateUpdateSchemaFields(
	descriptionsByName map[string]client.SchemaDescription,
	existingDesc client.SchemaDescription,
	proposedDesc client.SchemaDescription,
) (bool, error) {
	hasChanged := false
	existingFieldsByName := map[string]client.SchemaFieldDescription{}
	existingFieldIndexesByName := map[string]int{}
	for i, field := range existingDesc.Fields {
		existingFieldIndexesByName[field.Name] = i
		existingFieldsByName[field.Name] = field
	}

	newFieldNames := map[string]struct{}{}
	for proposedIndex, proposedField := range proposedDesc.Fields {
		existingField, fieldAlreadyExists := existingFieldsByName[proposedField.Name]

		// If the field is new, then the collection has changed
		hasChanged = hasChanged || !fieldAlreadyExists

		if !fieldAlreadyExists && proposedField.Kind.IsObject() {
			_, relatedDescFound := descriptionsByName[proposedField.Kind.Underlying()]

			if !relatedDescFound {
				return false, NewErrFieldKindNotFound(proposedField.Name, proposedField.Kind.Underlying())
			}

			if proposedField.Kind.IsObject() && !proposedField.Kind.IsArray() {
				idFieldName := proposedField.Name + request.RelatedObjectID
				idField, idFieldFound := proposedDesc.GetFieldByName(idFieldName)
				if idFieldFound {
					if idField.Kind != client.FieldKind_DocID {
						return false, NewErrRelationalFieldIDInvalidType(idField.Name, client.FieldKind_DocID, idField.Kind)
					}
				}
			}
		}

		if proposedField.Kind.IsObjectArray() {
			return false, NewErrSecondaryFieldOnSchema(proposedField.Name)
		}

		if _, isDuplicate := newFieldNames[proposedField.Name]; isDuplicate {
			return false, NewErrDuplicateField(proposedField.Name)
		}

		if fieldAlreadyExists && proposedField != existingField {
			return false, NewErrCannotMutateField(proposedField.Name)
		}

		if existingIndex := existingFieldIndexesByName[proposedField.Name]; fieldAlreadyExists &&
			proposedIndex != existingIndex {
			return false, NewErrCannotMoveField(proposedField.Name, proposedIndex, existingIndex)
		}

		if !proposedField.Typ.IsSupportedFieldCType() {
			return false, client.NewErrInvalidCRDTType(proposedField.Name, proposedField.Typ.String())
		}

		if !proposedField.Typ.IsCompatibleWith(proposedField.Kind) {
			return false, client.NewErrCRDTKindMismatch(proposedField.Typ.String(), proposedField.Kind.String())
		}

		newFieldNames[proposedField.Name] = struct{}{}
	}

	for _, field := range existingDesc.Fields {
		if _, stillExists := newFieldNames[field.Name]; !stillExists {
			return false, NewErrCannotDeleteField(field.Name)
		}
	}
	return hasChanged, nil
}

func (db *db) patchCollection(
	ctx context.Context,
	patchString string,
) error {
	patch, err := jsonpatch.DecodePatch([]byte(patchString))
	if err != nil {
		return err
	}
	txn := mustGetContextTxn(ctx)
	cols, err := description.GetCollections(ctx, txn)
	if err != nil {
		return err
	}

	existingColsByID := map[uint32]client.CollectionDescription{}
	for _, col := range cols {
		existingColsByID[col.ID] = col
	}

	existingDescriptionJson, err := json.Marshal(existingColsByID)
	if err != nil {
		return err
	}

	newDescriptionJson, err := patch.Apply(existingDescriptionJson)
	if err != nil {
		return err
	}

	var newColsByID map[uint32]client.CollectionDescription
	decoder := json.NewDecoder(strings.NewReader(string(newDescriptionJson)))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newColsByID)
	if err != nil {
		return err
	}

	err = db.validateCollectionChanges(existingColsByID, newColsByID)
	if err != nil {
		return err
	}

	for _, col := range newColsByID {
		_, err := description.SaveCollection(ctx, txn, col)
		if err != nil {
			return err
		}

		existingCol, ok := existingColsByID[col.ID]
		if ok {
			// Clear any existing migrations in the registry, using this semi-hacky way
			// to avoid adding more functions to a public interface that we wish to remove.

			for _, src := range existingCol.CollectionSources() {
				if src.Transform.HasValue() {
					err = db.LensRegistry().SetMigration(ctx, existingCol.ID, model.Lens{})
					if err != nil {
						return err
					}
				}
			}
			for _, src := range existingCol.QuerySources() {
				if src.Transform.HasValue() {
					err = db.LensRegistry().SetMigration(ctx, existingCol.ID, model.Lens{})
					if err != nil {
						return err
					}
				}
			}
		}

		for _, src := range col.CollectionSources() {
			if src.Transform.HasValue() {
				err = db.LensRegistry().SetMigration(ctx, col.ID, src.Transform.Value())
				if err != nil {
					return err
				}
			}
		}

		for _, src := range col.QuerySources() {
			if src.Transform.HasValue() {
				err = db.LensRegistry().SetMigration(ctx, col.ID, src.Transform.Value())
				if err != nil {
					return err
				}
			}
		}
	}

	return db.loadSchema(ctx)
}

var patchCollectionValidators = []func(
	map[uint32]client.CollectionDescription,
	map[uint32]client.CollectionDescription,
) error{
	validateCollectionNameUnique,
	validateSingleVersionActive,
	validateSourcesNotRedefined,
	validateIndexesNotModified,
	validateFieldsNotModified,
	validatePolicyNotModified,
	validateIDNotZero,
	validateIDUnique,
	validateIDExists,
	validateRootIDNotMutated,
	validateSchemaVersionIDNotMutated,
	validateCollectionNotRemoved,
}

func (db *db) validateCollectionChanges(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, validators := range patchCollectionValidators {
		err := validators(oldColsByID, newColsByID)
		if err != nil {
			return err
		}
	}

	return nil
}

var newCollectionValidators = []func(
	client.CollectionDefinition,
	map[string]client.CollectionDefinition,
) error{
	validateSecondaryFieldsPairUp,
	validateRelationPointsToValidKind,
	validateSingleSidePrimary,
}

func (db *db) validateNewCollection(
	def client.CollectionDefinition,
	defsByName map[string]client.CollectionDefinition,
) error {
	for _, validators := range newCollectionValidators {
		err := validators(def, defsByName)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateRelationPointsToValidKind(
	def client.CollectionDefinition,
	defsByName map[string]client.CollectionDefinition,
) error {
	for _, field := range def.Description.Fields {
		if !field.Kind.HasValue() {
			continue
		}

		if !field.Kind.Value().IsObject() {
			continue
		}

		underlying := field.Kind.Value().Underlying()
		_, ok := defsByName[underlying]
		if !ok {
			return NewErrFieldKindNotFound(field.Name, underlying)
		}
	}

	return nil
}

func validateSecondaryFieldsPairUp(
	def client.CollectionDefinition,
	defsByName map[string]client.CollectionDefinition,
) error {
	for _, field := range def.Description.Fields {
		if !field.Kind.HasValue() {
			continue
		}

		if !field.Kind.Value().IsObject() {
			continue
		}

		if !field.RelationName.HasValue() {
			continue
		}

		_, hasSchemaField := def.Schema.GetFieldByName(field.Name)
		if hasSchemaField {
			continue
		}

		underlying := field.Kind.Value().Underlying()
		otherDef, ok := defsByName[underlying]
		if !ok {
			continue
		}

		if len(otherDef.Description.Fields) == 0 {
			// Views/embedded objects do not require both sides of the relation to be defined.
			continue
		}

		otherField, ok := otherDef.Description.GetFieldByRelation(
			field.RelationName.Value(),
			def.GetName(),
			field.Name,
		)
		if !ok {
			return NewErrRelationMissingField(underlying, field.RelationName.Value())
		}

		_, ok = otherDef.Schema.GetFieldByName(otherField.Name)
		if !ok {
			// This secondary is paired with another secondary, which is invalid
			return NewErrRelationMissingField(underlying, field.RelationName.Value())
		}
	}

	return nil
}

func validateSingleSidePrimary(
	def client.CollectionDefinition,
	defsByName map[string]client.CollectionDefinition,
) error {
	for _, field := range def.Description.Fields {
		if !field.Kind.HasValue() {
			continue
		}

		if !field.Kind.Value().IsObject() {
			continue
		}

		if !field.RelationName.HasValue() {
			continue
		}

		_, hasSchemaField := def.Schema.GetFieldByName(field.Name)
		if !hasSchemaField {
			// This is a secondary field and thus passes this rule
			continue
		}

		underlying := field.Kind.Value().Underlying()
		otherDef, ok := defsByName[underlying]
		if !ok {
			continue
		}

		otherField, ok := otherDef.Description.GetFieldByRelation(
			field.RelationName.Value(),
			def.GetName(),
			field.Name,
		)
		if !ok {
			// This must be a one-sided relation, in which case it passes this rule
			continue
		}

		_, ok = otherDef.Schema.GetFieldByName(otherField.Name)
		if ok {
			// This primary is paired with another primary, which is invalid
			return ErrMultipleRelationPrimaries
		}
	}

	return nil
}

func validateCollectionNameUnique(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	names := map[string]struct{}{}
	for _, col := range newColsByID {
		if !col.Name.HasValue() {
			continue
		}

		if _, ok := names[col.Name.Value()]; ok {
			return NewErrCollectionAlreadyExists(col.Name.Value())
		}
		names[col.Name.Value()] = struct{}{}
	}

	return nil
}

func validateSingleVersionActive(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	rootsWithActiveCol := map[uint32]struct{}{}
	for _, col := range newColsByID {
		if !col.Name.HasValue() {
			continue
		}

		if _, ok := rootsWithActiveCol[col.RootID]; ok {
			return NewErrMultipleActiveCollectionVersions(col.Name.Value(), col.RootID)
		}
		rootsWithActiveCol[col.RootID] = struct{}{}
	}

	return nil
}

// validateSourcesNotRedefined specifies the limitations on how the collection sources
// can be mutated.
//
// Currently new sources cannot be added, existing cannot be removed, and CollectionSources
// cannot be redirected to other collections.
func validateSourcesNotRedefined(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		newColSources := newCol.CollectionSources()
		oldColSources := oldCol.CollectionSources()

		if len(newColSources) != len(oldColSources) {
			return NewErrCollectionSourcesCannotBeAddedRemoved(newCol.ID)
		}

		for i := range newColSources {
			if newColSources[i].SourceCollectionID != oldColSources[i].SourceCollectionID {
				return NewErrCollectionSourceIDMutated(
					newCol.ID,
					newColSources[i].SourceCollectionID,
					oldColSources[i].SourceCollectionID,
				)
			}
		}

		newQuerySources := newCol.QuerySources()
		oldQuerySources := oldCol.QuerySources()

		if len(newQuerySources) != len(oldQuerySources) {
			return NewErrCollectionSourcesCannotBeAddedRemoved(newCol.ID)
		}
	}

	return nil
}

func validateIndexesNotModified(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		// DeepEqual is temporary, as this validation is temporary
		if !reflect.DeepEqual(oldCol.Indexes, newCol.Indexes) {
			return NewErrCollectionIndexesCannotBeMutated(newCol.ID)
		}
	}

	return nil
}

func validateFieldsNotModified(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		// DeepEqual is temporary, as this validation is temporary
		if !reflect.DeepEqual(oldCol.Fields, newCol.Fields) {
			return NewErrCollectionFieldsCannotBeMutated(newCol.ID)
		}
	}

	return nil
}

func validatePolicyNotModified(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		// DeepEqual is temporary, as this validation is temporary
		if !reflect.DeepEqual(oldCol.Policy, newCol.Policy) {
			return NewErrCollectionPolicyCannotBeMutated(newCol.ID)
		}
	}

	return nil
}

func validateIDNotZero(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		if newCol.ID == 0 {
			return ErrCollectionIDCannotBeZero
		}
	}

	return nil
}

func validateIDUnique(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	colIds := map[uint32]struct{}{}
	for _, newCol := range newColsByID {
		if _, ok := colIds[newCol.ID]; ok {
			return NewErrCollectionIDAlreadyExists(newCol.ID)
		}
		colIds[newCol.ID] = struct{}{}
	}

	return nil
}

func validateIDExists(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		if _, ok := oldColsByID[newCol.ID]; !ok {
			return NewErrAddCollectionIDWithPatch(newCol.ID)
		}
	}

	return nil
}

func validateRootIDNotMutated(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		if newCol.RootID != oldCol.RootID {
			return NewErrCollectionRootIDCannotBeMutated(newCol.ID)
		}
	}

	return nil
}

func validateSchemaVersionIDNotMutated(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
	for _, newCol := range newColsByID {
		oldCol, ok := oldColsByID[newCol.ID]
		if !ok {
			continue
		}

		if newCol.SchemaVersionID != oldCol.SchemaVersionID {
			return NewErrCollectionSchemaVersionIDCannotBeMutated(newCol.ID)
		}
	}

	return nil
}

func validateCollectionNotRemoved(
	oldColsByID map[uint32]client.CollectionDescription,
	newColsByID map[uint32]client.CollectionDescription,
) error {
oldLoop:
	for _, oldCol := range oldColsByID {
		for _, newCol := range newColsByID {
			// It is not enough to just match by the map index, in case the index does not pair
			// up with the ID (this can happen if a user moves the collection within the map)
			if newCol.ID == oldCol.ID {
				continue oldLoop
			}
		}

		return NewErrCollectionsCannotBeDeleted(oldCol.ID)
	}

	return nil
}

// SetActiveSchemaVersion activates all collection versions with the given schema version, and deactivates all
// those without it (if they share the same schema root).
//
// This will affect all operations interacting with the schema where a schema version is not explicitly
// provided.  This includes GQL queries and Collection operations.
//
// It will return an error if the provided schema version ID does not exist.
func (db *db) setActiveSchemaVersion(
	ctx context.Context,
	schemaVersionID string,
) error {
	if schemaVersionID == "" {
		return ErrSchemaVersionIDEmpty
	}
	txn := mustGetContextTxn(ctx)
	cols, err := description.GetCollectionsBySchemaVersionID(ctx, txn, schemaVersionID)
	if err != nil {
		return err
	}

	schema, err := description.GetSchemaVersion(ctx, txn, schemaVersionID)
	if err != nil {
		return err
	}

	colsWithRoot, err := description.GetCollectionsBySchemaRoot(ctx, txn, schema.Root)
	if err != nil {
		return err
	}

	colsBySourceID := map[uint32][]client.CollectionDescription{}
	colsByID := make(map[uint32]client.CollectionDescription, len(colsWithRoot))
	for _, col := range colsWithRoot {
		colsByID[col.ID] = col

		sources := col.CollectionSources()
		if len(sources) > 0 {
			// For now, we assume that each collection can only have a single source.  This will likely need
			// to change later.
			slice := colsBySourceID[sources[0].SourceCollectionID]
			slice = append(slice, col)
			colsBySourceID[sources[0].SourceCollectionID] = slice
		}
	}

	for _, col := range cols {
		if col.Name.HasValue() {
			// The collection is already active, so we can skip it and continue
			continue
		}
		sources := col.CollectionSources()

		var activeCol client.CollectionDescription
		var rootCol client.CollectionDescription
		var isActiveFound bool
		if len(sources) > 0 {
			// For now, we assume that each collection can only have a single source.  This will likely need
			// to change later.
			activeCol, rootCol, isActiveFound = db.getActiveCollectionDown(ctx, colsByID, sources[0].SourceCollectionID)
		}
		if !isActiveFound {
			// We need to look both down and up for the active version - the most recent is not necessarily the active one.
			activeCol, isActiveFound = db.getActiveCollectionUp(ctx, colsBySourceID, rootCol.ID)
		}

		var newName string
		if isActiveFound {
			newName = activeCol.Name.Value()
		} else {
			// If there are no active versions in the collection set, take the name of the schema to be the name of the
			// collection.
			newName = schema.Name
		}
		col.Name = immutable.Some(newName)

		_, err = description.SaveCollection(ctx, txn, col)
		if err != nil {
			return err
		}

		if isActiveFound {
			// Deactivate the currently active collection by setting its name to none.
			activeCol.Name = immutable.None[string]()
			_, err = description.SaveCollection(ctx, txn, activeCol)
			if err != nil {
				return err
			}
		}
	}

	// Load the schema into the clients (e.g. GQL)
	return db.loadSchema(ctx)
}

func (db *db) getActiveCollectionDown(
	ctx context.Context,
	colsByID map[uint32]client.CollectionDescription,
	id uint32,
) (client.CollectionDescription, client.CollectionDescription, bool) {
	col, ok := colsByID[id]
	if !ok {
		return client.CollectionDescription{}, client.CollectionDescription{}, false
	}

	if col.Name.HasValue() {
		return col, client.CollectionDescription{}, true
	}

	sources := col.CollectionSources()
	if len(sources) == 0 {
		// If a collection has zero sources it is likely the initial collection version, or
		// this collection set is currently orphaned (can happen when setting migrations that
		// do not yet link all the way back to a non-orphaned set)
		return client.CollectionDescription{}, col, false
	}

	// For now, we assume that each collection can only have a single source.  This will likely need
	// to change later.
	return db.getActiveCollectionDown(ctx, colsByID, sources[0].SourceCollectionID)
}

func (db *db) getActiveCollectionUp(
	ctx context.Context,
	colsBySourceID map[uint32][]client.CollectionDescription,
	id uint32,
) (client.CollectionDescription, bool) {
	cols, ok := colsBySourceID[id]
	if !ok {
		// We have reached the top of the set, and have not found an active collection
		return client.CollectionDescription{}, false
	}

	for _, col := range cols {
		if col.Name.HasValue() {
			return col, true
		}
		activeCol, isFound := db.getActiveCollectionUp(ctx, colsBySourceID, col.ID)
		if isFound {
			return activeCol, isFound
		}
	}

	return client.CollectionDescription{}, false
}

func (db *db) getCollectionByID(ctx context.Context, id uint32) (client.Collection, error) {
	txn := mustGetContextTxn(ctx)

	col, err := description.GetCollectionByID(ctx, txn, id)
	if err != nil {
		return nil, err
	}

	schema, err := description.GetSchemaVersion(ctx, txn, col.SchemaVersionID)
	if err != nil {
		return nil, err
	}

	collection := db.newCollection(col, schema)

	err = collection.loadIndexes(ctx)
	if err != nil {
		return nil, err
	}

	return collection, nil
}

// getCollectionByName returns an existing collection within the database.
func (db *db) getCollectionByName(ctx context.Context, name string) (client.Collection, error) {
	if name == "" {
		return nil, ErrCollectionNameEmpty
	}

	cols, err := db.getCollections(ctx, client.CollectionFetchOptions{Name: immutable.Some(name)})
	if err != nil {
		return nil, err
	}

	// cols will always have length == 1 here
	return cols[0], nil
}

// getCollections returns all collections and their descriptions matching the given options
// that currently exist within this [Store].
//
// Inactive collections are not returned by default unless a specific schema version ID
// is provided.
func (db *db) getCollections(
	ctx context.Context,
	options client.CollectionFetchOptions,
) ([]client.Collection, error) {
	txn := mustGetContextTxn(ctx)

	var cols []client.CollectionDescription
	switch {
	case options.Name.HasValue():
		col, err := description.GetCollectionByName(ctx, txn, options.Name.Value())
		if err != nil {
			return nil, err
		}
		cols = append(cols, col)

	case options.SchemaVersionID.HasValue():
		var err error
		cols, err = description.GetCollectionsBySchemaVersionID(ctx, txn, options.SchemaVersionID.Value())
		if err != nil {
			return nil, err
		}

	case options.SchemaRoot.HasValue():
		var err error
		cols, err = description.GetCollectionsBySchemaRoot(ctx, txn, options.SchemaRoot.Value())
		if err != nil {
			return nil, err
		}

	default:
		if options.IncludeInactive.HasValue() && options.IncludeInactive.Value() {
			var err error
			cols, err = description.GetCollections(ctx, txn)
			if err != nil {
				return nil, err
			}
		} else {
			var err error
			cols, err = description.GetActiveCollections(ctx, txn)
			if err != nil {
				return nil, err
			}
		}
	}

	collections := []client.Collection{}
	for _, col := range cols {
		if options.SchemaVersionID.HasValue() {
			if col.SchemaVersionID != options.SchemaVersionID.Value() {
				continue
			}
		}
		// By default, we don't return inactive collections unless a specific version is requested.
		if !options.IncludeInactive.Value() && !col.Name.HasValue() && !options.SchemaVersionID.HasValue() {
			continue
		}

		schema, err := description.GetSchemaVersion(ctx, txn, col.SchemaVersionID)
		if err != nil {
			// If the schema is not found we leave it as empty and carry on. This can happen when
			// a migration is registered before the schema is declared locally.
			if !errors.Is(err, ds.ErrNotFound) {
				return nil, err
			}
		}

		if options.SchemaRoot.HasValue() {
			if schema.Root != options.SchemaRoot.Value() {
				continue
			}
		}

		collection := db.newCollection(col, schema)
		collections = append(collections, collection)

		err = collection.loadIndexes(ctx)
		if err != nil {
			return nil, err
		}
	}

	return collections, nil
}

// getAllActiveDefinitions returns all queryable collection/views and any embedded schema used by them.
func (db *db) getAllActiveDefinitions(ctx context.Context) ([]client.CollectionDefinition, error) {
	txn := mustGetContextTxn(ctx)

	cols, err := description.GetActiveCollections(ctx, txn)
	if err != nil {
		return nil, err
	}

	definitions := make([]client.CollectionDefinition, len(cols))
	for i, col := range cols {
		schema, err := description.GetSchemaVersion(ctx, txn, col.SchemaVersionID)
		if err != nil {
			return nil, err
		}

		collection := db.newCollection(col, schema)

		err = collection.loadIndexes(ctx)
		if err != nil {
			return nil, err
		}

		definitions[i] = collection.Definition()
	}

	schemas, err := description.GetCollectionlessSchemas(ctx, txn)
	if err != nil {
		return nil, err
	}

	for _, schema := range schemas {
		definitions = append(
			definitions,
			client.CollectionDefinition{
				Schema: schema,
			},
		)
	}

	return definitions, nil
}

// GetAllDocIDs returns all the document IDs that exist in the collection.
//
// @todo: We probably need a lock on the collection for this kind of op since
// it hits every key and will cause Tx conflicts for concurrent Txs
func (c *collection) GetAllDocIDs(
	ctx context.Context,
) (<-chan client.DocIDResult, error) {
	ctx, _, err := ensureContextTxn(ctx, c.db, true)
	if err != nil {
		return nil, err
	}
	return c.getAllDocIDsChan(ctx)
}

func (c *collection) getAllDocIDsChan(
	ctx context.Context,
) (<-chan client.DocIDResult, error) {
	txn := mustGetContextTxn(ctx)
	prefix := core.PrimaryDataStoreKey{ // empty path for all keys prefix
		CollectionRootID: c.Description().RootID,
	}
	q, err := txn.Datastore().Query(ctx, query.Query{
		Prefix:   prefix.ToString(),
		KeysOnly: true,
	})
	if err != nil {
		return nil, err
	}

	resCh := make(chan client.DocIDResult)
	go func() {
		defer func() {
			if err := q.Close(); err != nil {
				log.ErrorContextE(ctx, errFailedtoCloseQueryReqAllIDs, err)
			}
			close(resCh)
			txn.Discard(ctx)
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
				resCh <- client.DocIDResult{
					Err: res.Error,
				}
				return
			}

			rawDocID := ds.NewKey(res.Key).BaseNamespace()
			docID, err := client.NewDocIDFromString(rawDocID)
			if err != nil {
				resCh <- client.DocIDResult{
					Err: err,
				}
				return
			}

			canRead, err := c.checkAccessOfDocWithACP(
				ctx,
				acp.ReadPermission,
				docID.String(),
			)

			if err != nil {
				resCh <- client.DocIDResult{
					Err: err,
				}
				return
			}

			if canRead {
				resCh <- client.DocIDResult{
					ID: docID,
				}
			}
		}
	}()

	return resCh, nil
}

// Description returns the client.CollectionDescription.
func (c *collection) Description() client.CollectionDescription {
	return c.Definition().Description
}

// Name returns the collection name.
func (c *collection) Name() immutable.Option[string] {
	return c.Description().Name
}

// Schema returns the Schema of the collection.
func (c *collection) Schema() client.SchemaDescription {
	return c.Definition().Schema
}

// ID returns the ID of the collection.
func (c *collection) ID() uint32 {
	return c.Description().ID
}

func (c *collection) SchemaRoot() string {
	return c.Schema().Root
}

func (c *collection) Definition() client.CollectionDefinition {
	return c.def
}

// Create a new document.
// Will verify the DocID/CID to ensure that the new document is correctly formatted.
func (c *collection) Create(
	ctx context.Context,
	doc *client.Document,
) error {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	err = c.create(ctx, doc)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// CreateMany creates a collection of documents at once.
// Will verify the DocID/CID to ensure that the new documents are correctly formatted.
func (c *collection) CreateMany(
	ctx context.Context,
	docs []*client.Document,
) error {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	for _, doc := range docs {
		err = c.create(ctx, doc)
		if err != nil {
			return err
		}
	}
	return txn.Commit(ctx)
}

func (c *collection) getDocIDAndPrimaryKeyFromDoc(
	doc *client.Document,
) (client.DocID, core.PrimaryDataStoreKey, error) {
	docID, err := doc.GenerateDocID()
	if err != nil {
		return client.DocID{}, core.PrimaryDataStoreKey{}, err
	}

	primaryKey := c.getPrimaryKeyFromDocID(docID)
	if primaryKey.DocID != doc.ID().String() {
		return client.DocID{}, core.PrimaryDataStoreKey{},
			NewErrDocVerification(doc.ID().String(), primaryKey.DocID)
	}
	return docID, primaryKey, nil
}

func (c *collection) create(
	ctx context.Context,
	doc *client.Document,
) error {
	docID, primaryKey, err := c.getDocIDAndPrimaryKeyFromDoc(doc)
	if err != nil {
		return err
	}

	// check if doc already exists
	exists, isDeleted, err := c.exists(ctx, primaryKey)
	if err != nil {
		return err
	}
	if exists {
		return NewErrDocumentAlreadyExists(primaryKey.DocID)
	}
	if isDeleted {
		return NewErrDocumentDeleted(primaryKey.DocID)
	}

	// write value object marker if we have an empty doc
	if len(doc.Values()) == 0 {
		txn := mustGetContextTxn(ctx)
		valueKey := c.getDataStoreKeyFromDocID(docID)
		err = txn.Datastore().Put(ctx, valueKey.ToDS(), []byte{base.ObjectMarker})
		if err != nil {
			return err
		}
	}

	// write data to DB via MerkleClock/CRDT
	_, err = c.save(ctx, doc, true)
	if err != nil {
		return err
	}

	err = c.indexNewDoc(ctx, doc)
	if err != nil {
		return err
	}

	return c.registerDocWithACP(ctx, doc.ID().String())
}

// Update an existing document with the new values.
// Any field that needs to be removed or cleared should call doc.Clear(field) before.
// Any field that is nil/empty that hasn't called Clear will be ignored.
func (c *collection) Update(
	ctx context.Context,
	doc *client.Document,
) error {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	primaryKey := c.getPrimaryKeyFromDocID(doc.ID())
	exists, isDeleted, err := c.exists(ctx, primaryKey)
	if err != nil {
		return err
	}
	if !exists {
		return client.ErrDocumentNotFoundOrNotAuthorized
	}
	if isDeleted {
		return NewErrDocumentDeleted(primaryKey.DocID)
	}

	err = c.update(ctx, doc)
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// Contract: DB Exists check is already performed, and a doc with the given ID exists.
// Note: Should we CompareAndSet the update, IE: Query(read-only) the state, and update if changed
// or, just update everything regardless.
// Should probably be smart about the update due to the MerkleCRDT overhead, shouldn't
// add to the bloat.
func (c *collection) update(
	ctx context.Context,
	doc *client.Document,
) error {
	// Stop the update if the correct permissions aren't there.
	canUpdate, err := c.checkAccessOfDocWithACP(
		ctx,
		acp.WritePermission,
		doc.ID().String(),
	)
	if err != nil {
		return err
	}
	if !canUpdate {
		return client.ErrDocumentNotFoundOrNotAuthorized
	}

	_, err = c.save(ctx, doc, false)
	if err != nil {
		return err
	}
	return nil
}

// Save a document into the db.
// Either by creating a new document or by updating an existing one
func (c *collection) Save(
	ctx context.Context,
	doc *client.Document,
) error {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return err
	}
	defer txn.Discard(ctx)

	// Check if document already exists with primary DS key.
	primaryKey := c.getPrimaryKeyFromDocID(doc.ID())
	exists, isDeleted, err := c.exists(ctx, primaryKey)
	if err != nil {
		return err
	}

	if isDeleted {
		return NewErrDocumentDeleted(doc.ID().String())
	}

	if exists {
		err = c.update(ctx, doc)
	} else {
		err = c.create(ctx, doc)
	}
	if err != nil {
		return err
	}

	return txn.Commit(ctx)
}

// save saves the document state. save MUST not be called outside the `c.create`
// and `c.update` methods as we wrap the acp logic within those methods. Calling
// save elsewhere could cause the omission of acp checks.
func (c *collection) save(
	ctx context.Context,
	doc *client.Document,
	isCreate bool,
) (cid.Cid, error) {
	if !isCreate {
		err := c.updateIndexedDoc(ctx, doc)
		if err != nil {
			return cid.Undef, err
		}
	}
	txn := mustGetContextTxn(ctx)

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
	primaryKey := c.getPrimaryKeyFromDocID(doc.ID())
	links := make([]coreblock.DAGLink, 0)
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

			fieldDescription, valid := c.Definition().GetFieldByName(k)
			if !valid {
				return cid.Undef, client.NewErrFieldNotExist(k)
			}

			// by default the type will have been set to LWW_REGISTER. We need to ensure
			// that it's set to the same as the field description CRDT type.
			val.SetType(fieldDescription.Typ)

			relationFieldDescription, isSecondaryRelationID := c.isSecondaryIDField(fieldDescription)
			if isSecondaryRelationID {
				primaryId := val.Value().(string)

				err = c.patchPrimaryDoc(
					ctx,
					c.Name().Value(),
					relationFieldDescription,
					primaryKey.DocID,
					primaryId,
				)
				if err != nil {
					return cid.Undef, err
				}

				// If this field was a secondary relation ID the related document will have been
				// updated instead and we should discard this value
				continue
			}

			err = c.validateOneToOneLinkDoesntAlreadyExist(
				ctx,
				doc.ID().String(),
				fieldDescription,
				val.Value(),
			)
			if err != nil {
				return cid.Undef, err
			}

			merkleCRDT, err := merklecrdt.InstanceWithStore(
				txn,
				core.NewCollectionSchemaVersionKey(c.Schema().VersionID, c.ID()),
				val.Type(),
				fieldDescription.Kind,
				fieldKey,
				fieldDescription.Name,
			)
			if err != nil {
				return cid.Undef, err
			}

			link, _, err := merkleCRDT.Save(ctx, val)
			if err != nil {
				return cid.Undef, err
			}

			links = append(links, coreblock.NewDAGLink(k, link))
		}
	}

	link, headNode, err := c.saveCompositeToMerkleCRDT(
		ctx,
		primaryKey.ToDataStoreKey(),
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
						DocID:      doc.ID().String(),
						Cid:        link.Cid,
						SchemaRoot: c.Schema().Root,
						Block:      headNode,
						IsCreate:   isCreate,
					},
				)
			},
		)
	}

	txn.OnSuccess(func() {
		doc.SetHead(link.Cid)
	})

	return link.Cid, nil
}

func (c *collection) validateOneToOneLinkDoesntAlreadyExist(
	ctx context.Context,
	docID string,
	fieldDescription client.FieldDefinition,
	value any,
) error {
	if fieldDescription.Kind != client.FieldKind_DocID {
		return nil
	}

	if value == nil {
		return nil
	}

	objFieldDescription, ok := c.Definition().GetFieldByName(
		strings.TrimSuffix(fieldDescription.Name, request.RelatedObjectID),
	)
	if !ok {
		return client.NewErrFieldNotExist(strings.TrimSuffix(fieldDescription.Name, request.RelatedObjectID))
	}
	if !(objFieldDescription.Kind.IsObject() && !objFieldDescription.Kind.IsArray()) {
		return nil
	}

	otherCol, err := c.db.getCollectionByName(ctx, objFieldDescription.Kind.Underlying())
	if err != nil {
		return err
	}
	otherObjFieldDescription, _ := otherCol.Description().GetFieldByRelation(
		fieldDescription.RelationName,
		c.Name().Value(),
		objFieldDescription.Name,
	)
	if !(otherObjFieldDescription.Kind.HasValue() &&
		otherObjFieldDescription.Kind.Value().IsObject() &&
		!otherObjFieldDescription.Kind.Value().IsArray()) {
		// If the other field is not an object field then this is not a one to one relation and we can continue
		return nil
	}

	filter := fmt.Sprintf(
		`{_and: [{%s: {_ne: "%s"}}, {%s: {_eq: "%s"}}]}`,
		request.DocIDFieldName,
		docID,
		fieldDescription.Name,
		value,
	)
	selectionPlan, err := c.makeSelectionPlan(ctx, filter)
	if err != nil {
		return err
	}

	err = selectionPlan.Init()
	if err != nil {
		closeErr := selectionPlan.Close()
		if closeErr != nil {
			return errors.Wrap(err.Error(), closeErr)
		}
		return err
	}

	if err = selectionPlan.Start(); err != nil {
		closeErr := selectionPlan.Close()
		if closeErr != nil {
			return errors.Wrap(err.Error(), closeErr)
		}
		return err
	}

	alreadyLinked, err := selectionPlan.Next()
	if err != nil {
		closeErr := selectionPlan.Close()
		if closeErr != nil {
			return errors.Wrap(err.Error(), closeErr)
		}
		return err
	}

	if alreadyLinked {
		existingDocument := selectionPlan.Value()
		err := selectionPlan.Close()
		if err != nil {
			return err
		}
		return NewErrOneOneAlreadyLinked(docID, existingDocument.GetID(), objFieldDescription.RelationName)
	}

	err = selectionPlan.Close()
	if err != nil {
		return err
	}

	return nil
}

// Delete will attempt to delete a document by docID and return true if a deletion is successful,
// otherwise will return false, along with an error, if it cannot.
// If the document doesn't exist, then it will return false, and a ErrDocumentNotFound error.
// This operation will all state relating to the given DocID. This includes data, block, and head storage.
func (c *collection) Delete(
	ctx context.Context,
	docID client.DocID,
) (bool, error) {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return false, err
	}
	defer txn.Discard(ctx)

	primaryKey := c.getPrimaryKeyFromDocID(docID)

	err = c.applyDelete(ctx, primaryKey)
	if err != nil {
		return false, err
	}
	return true, txn.Commit(ctx)
}

// Exists checks if a given document exists with supplied DocID.
func (c *collection) Exists(
	ctx context.Context,
	docID client.DocID,
) (bool, error) {
	ctx, txn, err := ensureContextTxn(ctx, c.db, false)
	if err != nil {
		return false, err
	}
	defer txn.Discard(ctx)

	primaryKey := c.getPrimaryKeyFromDocID(docID)
	exists, isDeleted, err := c.exists(ctx, primaryKey)
	if err != nil && !errors.Is(err, ds.ErrNotFound) {
		return false, err
	}
	return exists && !isDeleted, txn.Commit(ctx)
}

// check if a document exists with the given primary key
func (c *collection) exists(
	ctx context.Context,
	primaryKey core.PrimaryDataStoreKey,
) (exists bool, isDeleted bool, err error) {
	canRead, err := c.checkAccessOfDocWithACP(
		ctx,
		acp.ReadPermission,
		primaryKey.DocID,
	)
	if err != nil {
		return false, false, err
	} else if !canRead {
		return false, false, nil
	}

	txn := mustGetContextTxn(ctx)
	val, err := txn.Datastore().Get(ctx, primaryKey.ToDS())
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

// saveCompositeToMerkleCRDT saves the composite to the merkle CRDT.
// It returns the CID of the block and the encoded block.
// saveCompositeToMerkleCRDT MUST not be called outside the `c.save`
// and `c.applyDelete` methods as we wrap the acp logic around those methods.
// Calling it elsewhere could cause the omission of acp checks.
func (c *collection) saveCompositeToMerkleCRDT(
	ctx context.Context,
	dsKey core.DataStoreKey,
	links []coreblock.DAGLink,
	status client.DocumentStatus,
) (cidlink.Link, []byte, error) {
	txn := mustGetContextTxn(ctx)
	dsKey = dsKey.WithFieldId(core.COMPOSITE_NAMESPACE)
	merkleCRDT := merklecrdt.NewMerkleCompositeDAG(
		txn,
		core.NewCollectionSchemaVersionKey(c.Schema().VersionID, c.ID()),
		dsKey,
		"",
	)

	if status.IsDeleted() {
		return merkleCRDT.Delete(ctx, links)
	}

	return merkleCRDT.Save(ctx, links)
}

func (c *collection) getPrimaryKeyFromDocID(docID client.DocID) core.PrimaryDataStoreKey {
	return core.PrimaryDataStoreKey{
		CollectionRootID: c.Description().RootID,
		DocID:            docID.String(),
	}
}

func (c *collection) getDataStoreKeyFromDocID(docID client.DocID) core.DataStoreKey {
	return core.DataStoreKey{
		CollectionRootID: c.Description().RootID,
		DocID:            docID.String(),
		InstanceType:     core.ValueKey,
	}
}

func (c *collection) tryGetFieldKey(primaryKey core.PrimaryDataStoreKey, fieldName string) (core.DataStoreKey, bool) {
	fieldId, hasField := c.tryGetFieldID(fieldName)
	if !hasField {
		return core.DataStoreKey{}, false
	}

	return core.DataStoreKey{
		CollectionRootID: c.Description().RootID,
		DocID:            primaryKey.DocID,
		FieldId:          strconv.FormatUint(uint64(fieldId), 10),
	}, true
}

// tryGetFieldID returns the FieldID of the given fieldName.
// Will return false if the field is not found.
func (c *collection) tryGetFieldID(fieldName string) (uint32, bool) {
	for _, field := range c.Definition().GetFields() {
		if field.Name == fieldName {
			if field.Kind.IsObject() || field.Kind.IsObjectArray() {
				// We do not wish to match navigational properties, only
				// fields directly on the collection.
				return uint32(0), false
			}
			return uint32(field.ID), true
		}
	}

	return uint32(0), false
}
