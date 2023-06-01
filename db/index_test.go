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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/datastore/mocks"
	"github.com/sourcenetwork/defradb/errors"
)

const (
	usersColName    = "Users"
	productsColName = "Products"

	usersNameFieldName   = "name"
	usersAgeFieldName    = "age"
	usersWeightFieldName = "weight"

	productsIDFieldName        = "id"
	productsPriceFieldName     = "price"
	productsCategoryFieldName  = "category"
	productsAvailableFieldName = "available"

	testUsersColIndexName   = "user_name"
	testUsersColIndexAge    = "user_age"
	testUsersColIndexWeight = "user_weight"

	userColVersionID = "bafkreiefzlx2xsfaxixs24hcqwwqpa3nuqbutkapasymk3d5v4fxa4rlhy"
)

type indexTestFixture struct {
	ctx   context.Context
	db    *implicitTxnDB
	txn   datastore.Txn
	users *collection
	t     *testing.T
}

func getUsersCollectionDesc() client.CollectionDescription {
	return client.CollectionDescription{
		Name: usersColName,
		Schema: client.SchemaDescription{
			Fields: []client.FieldDescription{
				{
					Name: "_key",
					Kind: client.FieldKind_DocKey,
				},
				{
					Name: usersNameFieldName,
					Kind: client.FieldKind_STRING,
					Typ:  client.LWW_REGISTER,
				},
				{
					Name: usersAgeFieldName,
					Kind: client.FieldKind_INT,
					Typ:  client.LWW_REGISTER,
				},
				{
					Name: usersWeightFieldName,
					Kind: client.FieldKind_FLOAT,
					Typ:  client.LWW_REGISTER,
				},
			},
		},
	}
}

func getProductsCollectionDesc() client.CollectionDescription {
	return client.CollectionDescription{
		Name: productsColName,
		Schema: client.SchemaDescription{
			Fields: []client.FieldDescription{
				{
					Name: "_key",
					Kind: client.FieldKind_DocKey,
				},
				{
					Name: productsIDFieldName,
					Kind: client.FieldKind_INT,
					Typ:  client.LWW_REGISTER,
				},
				{
					Name: productsPriceFieldName,
					Kind: client.FieldKind_FLOAT,
					Typ:  client.LWW_REGISTER,
				},
				{
					Name: productsCategoryFieldName,
					Kind: client.FieldKind_STRING,
					Typ:  client.LWW_REGISTER,
				},
				{
					Name: productsAvailableFieldName,
					Kind: client.FieldKind_BOOL,
					Typ:  client.LWW_REGISTER,
				},
			},
		},
	}
}

func newIndexTestFixtureBare(t *testing.T) *indexTestFixture {
	ctx := context.Background()
	db, err := newMemoryDB(ctx)
	require.NoError(t, err)
	txn, err := db.NewTxn(ctx, false)
	require.NoError(t, err)

	return &indexTestFixture{
		ctx: ctx,
		db:  db,
		txn: txn,
		t:   t,
	}
}

func newIndexTestFixture(t *testing.T) *indexTestFixture {
	f := newIndexTestFixtureBare(t)
	f.users = f.createCollection(getUsersCollectionDesc())
	return f
}

func (f *indexTestFixture) createCollectionIndex(
	desc client.IndexDescription,
) (client.IndexDescription, error) {
	return f.createCollectionIndexFor(f.users.Name(), desc)
}

func getUsersIndexDescOnName() client.IndexDescription {
	return client.IndexDescription{
		Name: testUsersColIndexName,
		Fields: []client.IndexedFieldDescription{
			{Name: usersNameFieldName, Direction: client.Ascending},
		},
	}
}

func getUsersIndexDescOnAge() client.IndexDescription {
	return client.IndexDescription{
		Name: testUsersColIndexAge,
		Fields: []client.IndexedFieldDescription{
			{Name: usersAgeFieldName, Direction: client.Ascending},
		},
	}
}

func getUsersIndexDescOnWeight() client.IndexDescription {
	return client.IndexDescription{
		Name: testUsersColIndexWeight,
		Fields: []client.IndexedFieldDescription{
			{Name: usersWeightFieldName, Direction: client.Ascending},
		},
	}
}

func getProductsIndexDescOnCategory() client.IndexDescription {
	return client.IndexDescription{
		Name: testUsersColIndexAge,
		Fields: []client.IndexedFieldDescription{
			{Name: productsCategoryFieldName, Direction: client.Ascending},
		},
	}
}

func (f *indexTestFixture) createUserCollectionIndexOnName() client.IndexDescription {
	newDesc, err := f.createCollectionIndexFor(f.users.Name(), getUsersIndexDescOnName())
	require.NoError(f.t, err)
	f.commitTxn()
	return newDesc
}

func (f *indexTestFixture) createUserCollectionIndexOnAge() client.IndexDescription {
	newDesc, err := f.createCollectionIndexFor(f.users.Name(), getUsersIndexDescOnAge())
	require.NoError(f.t, err)
	f.commitTxn()
	return newDesc
}

func (f *indexTestFixture) dropIndex(colName, indexName string) error {
	return f.db.dropCollectionIndex(f.ctx, f.txn, colName, indexName)
}

func (f *indexTestFixture) dropAllIndexes(colName string) error {
	col := (f.users.WithTxn(f.txn)).(*collection)
	return col.dropAllIndexes(f.ctx)
}

func (f *indexTestFixture) countIndexPrefixes(colName, indexName string) int {
	prefix := core.NewCollectionIndexKey(usersColName, indexName)
	q, err := f.txn.Systemstore().Query(f.ctx, query.Query{
		Prefix: prefix.ToString(),
	})
	assert.NoError(f.t, err)
	defer func() {
		err := q.Close()
		assert.NoError(f.t, err)
	}()

	count := 0
	for res := range q.Next() {
		if res.Error != nil {
			assert.NoError(f.t, err)
		}
		count++
	}
	return count
}

func (f *indexTestFixture) commitTxn() {
	err := f.txn.Commit(f.ctx)
	require.NoError(f.t, err)
	txn, err := f.db.NewTxn(f.ctx, false)
	require.NoError(f.t, err)
	f.txn = txn
}

func (f *indexTestFixture) createCollectionIndexFor(
	collectionName string,
	desc client.IndexDescription,
) (client.IndexDescription, error) {
	newDesc, err := f.db.createCollectionIndex(f.ctx, f.txn, collectionName, desc)
	//if err != nil {
	//return newDesc, err
	//}
	//f.txn, err = f.db.NewTxn(f.ctx, false)
	//assert.NoError(f.t, err)
	return newDesc, err
}

func (f *indexTestFixture) getAllIndexes() ([]client.CollectionIndexDescription, error) {
	return f.db.getAllCollectionIndexes(f.ctx, f.txn)
}

func (f *indexTestFixture) getCollectionIndexes(colName string) ([]client.IndexDescription, error) {
	return f.db.getCollectionIndexes(f.ctx, f.txn, colName)
}

func (f *indexTestFixture) createCollection(
	desc client.CollectionDescription,
) *collection {
	col, err := f.db.createCollection(f.ctx, f.txn, desc)
	assert.NoError(f.t, err)
	err = f.txn.Commit(f.ctx)
	assert.NoError(f.t, err)
	f.txn, err = f.db.NewTxn(f.ctx, false)
	assert.NoError(f.t, err)
	return col.(*collection)
}

func TestCreateIndex_IfFieldsIsEmpty_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	_, err := f.createCollectionIndex(client.IndexDescription{
		Name: "some_index_name",
	})
	assert.EqualError(t, err, errIndexMissingFields)
}

func TestCreateIndex_IfIndexDescriptionIDIsNotZero_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	for _, id := range []uint32{1, 20, 999} {
		desc := client.IndexDescription{
			Name: "some_index_name",
			ID:   id,
			Fields: []client.IndexedFieldDescription{
				{Name: usersNameFieldName, Direction: client.Ascending},
			},
		}
		_, err := f.createCollectionIndex(desc)
		assert.ErrorIs(t, err, NewErrNonZeroIndexIDProvided(0))
	}
}

func TestCreateIndex_IfValidInput_CreateIndex(t *testing.T) {
	f := newIndexTestFixture(t)

	desc := client.IndexDescription{
		Name: "some_index_name",
		Fields: []client.IndexedFieldDescription{
			{Name: usersNameFieldName, Direction: client.Ascending},
		},
	}
	resultDesc, err := f.createCollectionIndex(desc)
	assert.NoError(t, err)
	assert.Equal(t, desc.Name, resultDesc.Name)
	assert.Equal(t, desc.Fields, resultDesc.Fields)
	assert.Equal(t, desc.Unique, resultDesc.Unique)
}

func TestCreateIndex_IfFieldNameIsEmpty_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	desc := client.IndexDescription{
		Name: "some_index_name",
		Fields: []client.IndexedFieldDescription{
			{Name: "", Direction: client.Ascending},
		},
	}
	_, err := f.createCollectionIndex(desc)
	assert.EqualError(t, err, errIndexFieldMissingName)
}

func TestCreateIndex_IfFieldHasNoDirection_DefaultToAsc(t *testing.T) {
	f := newIndexTestFixture(t)

	desc := client.IndexDescription{
		Name:   "some_index_name",
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	newDesc, err := f.createCollectionIndex(desc)
	assert.NoError(t, err)
	assert.Equal(t, client.Ascending, newDesc.Fields[0].Direction)
}

func TestCreateIndex_IfNameIsNotSpecified_GenerateWithLowerCase(t *testing.T) {
	f := newIndexTestFixtureBare(t)
	colDesc := getUsersCollectionDesc()
	const colName = "UsErS"
	const fieldName = "NaMe"
	colDesc.Name = colName
	colDesc.Schema.Name = colName // Which one should we use?
	colDesc.Schema.Fields[1].Name = fieldName
	f.users = f.createCollection(colDesc)

	desc := client.IndexDescription{
		Name: "",
		Fields: []client.IndexedFieldDescription{
			{Name: fieldName, Direction: client.Ascending},
		},
	}

	newDesc, err := f.createCollectionIndex(desc)
	assert.NoError(t, err)
	assert.Equal(t, colName+"_"+fieldName+"_ASC", newDesc.Name)
}

func TestCreateIndex_IfSingleFieldInDescOrder_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	desc := client.IndexDescription{
		Fields: []client.IndexedFieldDescription{
			{Name: usersNameFieldName, Direction: client.Descending},
		},
	}
	_, err := f.createCollectionIndex(desc)
	assert.EqualError(t, err, errIndexSingleFieldWrongDirection)
}

func TestCreateIndex_IfIndexWithNameAlreadyExists_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	name := "some_index_name"
	desc1 := client.IndexDescription{
		Name:   name,
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	desc2 := client.IndexDescription{
		Name:   name,
		Fields: []client.IndexedFieldDescription{{Name: usersAgeFieldName}},
	}
	_, err := f.createCollectionIndex(desc1)
	assert.NoError(t, err)
	_, err = f.createCollectionIndex(desc2)
	assert.EqualError(t, err, errIndexWithNameAlreadyExists)
}

func TestCreateIndex_IfGeneratedNameMatchesExisting_AddIncrement(t *testing.T) {
	f := newIndexTestFixture(t)

	name := usersColName + "_" + usersAgeFieldName + "_ASC"
	desc1 := client.IndexDescription{
		Name:   name,
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	desc2 := client.IndexDescription{
		Name:   name + "_2",
		Fields: []client.IndexedFieldDescription{{Name: usersWeightFieldName}},
	}
	desc3 := client.IndexDescription{
		Name:   "",
		Fields: []client.IndexedFieldDescription{{Name: usersAgeFieldName}},
	}
	_, err := f.createCollectionIndex(desc1)
	assert.NoError(t, err)
	_, err = f.createCollectionIndex(desc2)
	assert.NoError(t, err)
	newDesc3, err := f.createCollectionIndex(desc3)
	assert.NoError(t, err)
	assert.Equal(t, name+"_3", newDesc3.Name)
}

func TestCreateIndex_ShouldSaveToSystemStorage(t *testing.T) {
	f := newIndexTestFixture(t)

	name := "users_age_ASC"
	desc := client.IndexDescription{
		Name:   name,
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	_, err := f.createCollectionIndex(desc)
	assert.NoError(t, err)

	key := core.NewCollectionIndexKey(f.users.Name(), name)
	data, err := f.txn.Systemstore().Get(f.ctx, key.ToDS())
	assert.NoError(t, err)
	var deserialized client.IndexDescription
	err = json.Unmarshal(data, &deserialized)
	assert.NoError(t, err)
	desc.ID = 1
	assert.Equal(t, desc, deserialized)
}

func TestCreateIndex_IfStorageFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	name := "users_age_ASC"
	desc := client.IndexDescription{
		Name:   name,
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}

	f.db.Close(f.ctx)

	_, err := f.createCollectionIndex(desc)
	assert.Error(t, err)
}

func TestCreateIndex_IfCollectionDoesntExist_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	desc := client.IndexDescription{
		Fields: []client.IndexedFieldDescription{{Name: productsPriceFieldName}},
	}

	_, err := f.createCollectionIndexFor(productsColName, desc)
	assert.ErrorIs(t, err, NewErrCollectionDoesntExist(usersColName))
}

func TestCreateIndex_IfPropertyDoesntExist_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	const field = "non_existing_field"
	desc := client.IndexDescription{
		Fields: []client.IndexedFieldDescription{{Name: field}},
	}

	_, err := f.createCollectionIndex(desc)
	assert.ErrorIs(t, err, NewErrNonExistingFieldForIndex(field))
}

func TestCreateIndex_WithMultipleCollectionsAndIndexes_AssignIncrementedIDPerCollection(t *testing.T) {
	f := newIndexTestFixtureBare(t)
	users := f.createCollection(getUsersCollectionDesc())
	products := f.createCollection(getProductsCollectionDesc())

	makeIndex := func(fieldName string) client.IndexDescription {
		return client.IndexDescription{
			Fields: []client.IndexedFieldDescription{
				{Name: fieldName, Direction: client.Ascending},
			},
		}
	}

	createIndexAndAssert := func(col client.Collection, fieldName string, expectedID uint32) {
		desc, err := f.createCollectionIndexFor(col.Name(), makeIndex(fieldName))
		require.NoError(t, err)
		assert.Equal(t, expectedID, desc.ID)
		seqKey := core.NewSequenceKey(fmt.Sprintf("%s/%d", core.COLLECTION_INDEX, col.ID()))
		storedSeqKey, err := f.txn.Systemstore().Get(f.ctx, seqKey.ToDS())
		assert.NoError(t, err)
		storedSeqVal := binary.BigEndian.Uint64(storedSeqKey)
		assert.Equal(t, expectedID, uint32(storedSeqVal))
	}

	createIndexAndAssert(users, usersNameFieldName, 1)
	createIndexAndAssert(users, usersAgeFieldName, 2)
	createIndexAndAssert(products, productsIDFieldName, 1)
	createIndexAndAssert(products, productsCategoryFieldName, 2)
}

func TestGetIndexes_ShouldReturnListOfAllExistingIndexes(t *testing.T) {
	f := newIndexTestFixture(t)

	usersIndexDesc := client.IndexDescription{
		Name:   "users_name_index",
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	_, err := f.createCollectionIndexFor(usersColName, usersIndexDesc)
	assert.NoError(t, err)

	f.createCollection(getProductsCollectionDesc())
	productsIndexDesc := client.IndexDescription{
		Name:   "products_description_index",
		Fields: []client.IndexedFieldDescription{{Name: productsPriceFieldName}},
	}
	_, err = f.createCollectionIndexFor(productsColName, productsIndexDesc)
	assert.NoError(t, err)

	indexes, err := f.getAllIndexes()
	assert.NoError(t, err)

	require.Equal(t, 2, len(indexes))
	usersIndexIndex := 0
	if indexes[0].CollectionName != usersColName {
		usersIndexIndex = 1
	}
	assert.Equal(t, usersIndexDesc.Name, indexes[usersIndexIndex].Index.Name)
	assert.Equal(t, usersColName, indexes[usersIndexIndex].CollectionName)
	assert.Equal(t, productsIndexDesc.Name, indexes[1-usersIndexIndex].Index.Name)
	assert.Equal(t, productsColName, indexes[1-usersIndexIndex].CollectionName)
}

func TestGetIndexes_IfInvalidIndexIsStored_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	indexKey := core.NewCollectionIndexKey(usersColName, "users_name_index")
	err := f.txn.Systemstore().Put(f.ctx, indexKey.ToDS(), []byte("invalid"))
	assert.NoError(t, err)

	_, err = f.getAllIndexes()
	assert.ErrorIs(t, err, NewErrInvalidStoredIndex(nil))
}

func TestGetIndexes_IfInvalidIndexKeyIsStored_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	indexKey := core.NewCollectionIndexKey(usersColName, "users_name_index")
	key := ds.NewKey(indexKey.ToString() + "/invalid")
	desc := client.IndexDescription{
		Name: "some_index_name",
		Fields: []client.IndexedFieldDescription{
			{Name: usersNameFieldName, Direction: client.Ascending},
		},
	}
	descData, _ := json.Marshal(desc)
	err := f.txn.Systemstore().Put(f.ctx, key, descData)
	assert.NoError(t, err)

	_, err = f.getAllIndexes()
	assert.ErrorIs(t, err, NewErrInvalidStoredIndexKey(key.String()))
}

func TestGetIndexes_IfSystemStoreFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	mockedTxn := f.mockTxn()

	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).Unset()
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).
		Return(nil, errors.New("test error"))

	_, err := f.getAllIndexes()
	assert.ErrorIs(t, err, NewErrFailedToCreateCollectionQuery(nil))
}

func TestGetIndexes_IfSystemStoreFails_ShouldCloseIterator(t *testing.T) {
	f := newIndexTestFixture(t)

	mockedTxn := f.mockTxn()
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).Unset()
	q := mocks.NewQueryResultsWithValues(t)
	q.EXPECT().Close().Return(nil)
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).Return(q, nil)

	_, _ = f.getAllIndexes()
}

func TestGetIndexes_IfSystemStoreQueryIteratorFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	testErr := errors.New("test error")

	mockedTxn := f.mockTxn()

	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).Unset()
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).
		Return(mocks.NewQueryResultsWithResults(t, query.Result{Error: testErr}), nil)

	_, err := f.getAllIndexes()
	assert.ErrorIs(t, err, testErr)
}

func TestGetIndexes_IfFailsToReadSeqNumber_ReturnError(t *testing.T) {
	testErr := errors.New("test error")

	testCases := []struct {
		Name            string
		StubSystemStore func(*mocks.DSReaderWriter_Expecter, core.Key)
	}{
		{
			Name: "Read Sequence Number",
			StubSystemStore: func(onSystemStore *mocks.DSReaderWriter_Expecter, seqKey core.Key) {
				onSystemStore.Get(mock.Anything, seqKey.ToDS()).Return(nil, testErr)
			},
		},
		{
			Name: "Increment Sequence Number",
			StubSystemStore: func(onSystemStore *mocks.DSReaderWriter_Expecter, seqKey core.Key) {
				onSystemStore.Put(mock.Anything, seqKey.ToDS(), mock.Anything).Return(testErr)
			},
		},
	}

	for _, tc := range testCases {
		f := newIndexTestFixture(t)

		mockedTxn := f.mockTxn()
		onSystemStore := mockedTxn.MockSystemstore.EXPECT()
		f.resetSystemStoreStubs(onSystemStore)

		seqKey := core.NewSequenceKey(fmt.Sprintf("%s/%d", core.COLLECTION_INDEX, f.users.ID()))
		tc.StubSystemStore(onSystemStore, seqKey)
		f.stubSystemStore(onSystemStore)

		_, err := f.createCollectionIndexFor(f.users.Name(), getUsersIndexDescOnName())
		assert.ErrorIs(t, err, testErr)
	}
}

func TestGetCollectionIndexes_ShouldReturnListOfCollectionIndexes(t *testing.T) {
	f := newIndexTestFixture(t)

	usersIndexDesc := client.IndexDescription{
		Name:   "users_name_index",
		Fields: []client.IndexedFieldDescription{{Name: usersNameFieldName}},
	}
	_, err := f.createCollectionIndexFor(usersColName, usersIndexDesc)
	assert.NoError(t, err)

	f.createCollection(getProductsCollectionDesc())
	productsIndexDesc := client.IndexDescription{
		Name:   "products_description_index",
		Fields: []client.IndexedFieldDescription{{Name: productsPriceFieldName}},
	}
	_, err = f.createCollectionIndexFor(productsColName, productsIndexDesc)
	assert.NoError(t, err)

	userIndexes, err := f.getCollectionIndexes(usersColName)
	assert.NoError(t, err)
	require.Equal(t, 1, len(userIndexes))
	usersIndexDesc.ID = 1
	assert.Equal(t, usersIndexDesc, userIndexes[0])

	productIndexes, err := f.getCollectionIndexes(productsColName)
	assert.NoError(t, err)
	require.Equal(t, 1, len(productIndexes))
	productsIndexDesc.ID = 1
	assert.Equal(t, productsIndexDesc, productIndexes[0])
}

func TestGetCollectionIndexes_IfSystemStoreFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	mockedTxn := f.mockTxn()
	mockedTxn.MockSystemstore = mocks.NewDSReaderWriter(t)
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).
		Return(nil, errors.New("test error"))
	mockedTxn.EXPECT().Systemstore().Unset()
	mockedTxn.EXPECT().Systemstore().Return(mockedTxn.MockSystemstore)

	_, err := f.getCollectionIndexes(usersColName)
	assert.ErrorIs(t, err, NewErrFailedToCreateCollectionQuery(nil))
}

func TestGetCollectionIndexes_IfSystemStoreFails_ShouldCloseIterator(t *testing.T) {
	f := newIndexTestFixture(t)

	mockedTxn := f.mockTxn()
	mockedTxn.MockSystemstore = mocks.NewDSReaderWriter(t)
	query := mocks.NewQueryResultsWithValues(t)
	query.EXPECT().Close().Return(nil)
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).Return(query, nil)
	mockedTxn.EXPECT().Systemstore().Unset()
	mockedTxn.EXPECT().Systemstore().Return(mockedTxn.MockSystemstore)

	_, _ = f.getCollectionIndexes(usersColName)
}

func TestGetCollectionIndexes_IfSystemStoreQueryIteratorFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	testErr := errors.New("test error")

	mockedTxn := f.mockTxn()
	mockedTxn.MockSystemstore = mocks.NewDSReaderWriter(t)
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).
		Return(mocks.NewQueryResultsWithResults(t, query.Result{Error: testErr}), nil)
	mockedTxn.EXPECT().Systemstore().Unset()
	mockedTxn.EXPECT().Systemstore().Return(mockedTxn.MockSystemstore)

	_, err := f.getCollectionIndexes(usersColName)
	assert.ErrorIs(t, err, testErr)
}

func TestGetCollectionIndexes_IfInvalidIndexIsStored_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	indexKey := core.NewCollectionIndexKey(usersColName, "users_name_index")
	err := f.txn.Systemstore().Put(f.ctx, indexKey.ToDS(), []byte("invalid"))
	assert.NoError(t, err)

	_, err = f.getCollectionIndexes(usersColName)
	assert.ErrorIs(t, err, NewErrInvalidStoredIndex(nil))
}

func TestCollectionGetIndexes_ShouldReturnIndexes(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	indexes, err := f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)

	require.Equal(t, 1, len(indexes))
	assert.Equal(t, testUsersColIndexName, indexes[0].Name)
}

func TestCollectionGetIndexes_IfCalledAgain_ShouldReturnCached(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	_, err := f.users.GetIndexes(f.ctx)
	require.NoError(t, err)

	mockedTxn := mocks.NewTxnWithMultistore(f.t)

	indexes, err := f.users.WithTxn(mockedTxn).GetIndexes(f.ctx)
	require.NoError(t, err)

	require.Equal(t, 1, len(indexes))
	assert.Equal(t, testUsersColIndexName, indexes[0].Name)
}

func TestCollectionGetIndexes_ShouldCloseQueryIterator(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	mockedTxn := f.mockTxn()

	mockedTxn.MockSystemstore = mocks.NewDSReaderWriter(f.t)
	mockedTxn.EXPECT().Systemstore().Unset()
	mockedTxn.EXPECT().Systemstore().Return(mockedTxn.MockSystemstore).Maybe()
	queryResults := mocks.NewQueryResultsWithValues(f.t)
	queryResults.EXPECT().Close().Unset()
	queryResults.EXPECT().Close().Return(nil)
	mockedTxn.MockSystemstore.EXPECT().Query(mock.Anything, mock.Anything).
		Return(queryResults, nil)

	_, err := f.users.WithTxn(mockedTxn).GetIndexes(f.ctx)
	assert.NoError(t, err)
}

func TestCollectionGetIndexes_IfSystemStoreFails_ShouldNotCache(t *testing.T) {
	testErr := errors.New("test error")

	testCases := []struct {
		Name               string
		ExpectedError      error
		GetMockSystemstore func(t *testing.T) *mocks.DSReaderWriter
	}{
		{
			Name:          "Query fails",
			ExpectedError: testErr,
			GetMockSystemstore: func(t *testing.T) *mocks.DSReaderWriter {
				store := mocks.NewDSReaderWriter(t)
				store.EXPECT().Query(mock.Anything, mock.Anything).Unset()
				store.EXPECT().Query(mock.Anything, mock.Anything).Return(nil, testErr)
				return store
			},
		},
		{
			Name:          "Query iterator fails",
			ExpectedError: testErr,
			GetMockSystemstore: func(t *testing.T) *mocks.DSReaderWriter {
				store := mocks.NewDSReaderWriter(t)
				store.EXPECT().Query(mock.Anything, mock.Anything).
					Return(mocks.NewQueryResultsWithResults(t, query.Result{Error: testErr}), nil)
				return store
			},
		},
		{
			Name:          "Query iterator returns invalid value",
			ExpectedError: NewErrInvalidStoredIndex(nil),
			GetMockSystemstore: func(t *testing.T) *mocks.DSReaderWriter {
				store := mocks.NewDSReaderWriter(t)
				store.EXPECT().Query(mock.Anything, mock.Anything).
					Return(mocks.NewQueryResultsWithValues(t, []byte("invalid")), nil)
				return store
			},
		},
	}

	for _, testCase := range testCases {
		f := newIndexTestFixture(t)

		f.createUserCollectionIndexOnName()

		mockedTxn := f.mockTxn()

		mockedTxn.MockSystemstore = testCase.GetMockSystemstore(t)
		mockedTxn.EXPECT().Systemstore().Unset()
		mockedTxn.EXPECT().Systemstore().Return(mockedTxn.MockSystemstore).Maybe()

		_, err := f.users.WithTxn(mockedTxn).GetIndexes(f.ctx)
		require.ErrorIs(t, err, testCase.ExpectedError)

		indexes, err := f.users.GetIndexes(f.ctx)
		require.NoError(t, err)

		require.Equal(t, 1, len(indexes))
		assert.Equal(t, testUsersColIndexName, indexes[0].Name)
	}
}

func TestCollectionGetIndexes_IfFailsToCreateTxn_ShouldNotCache(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	testErr := errors.New("test error")

	workingRootStore := f.db.rootstore
	mockedRootStore := mocks.NewRootStore(t)
	f.db.rootstore = mockedRootStore
	mockedRootStore.EXPECT().NewTransaction(mock.Anything, mock.Anything).Return(nil, testErr)

	_, err := f.users.GetIndexes(f.ctx)
	require.ErrorIs(t, err, testErr)

	f.db.rootstore = workingRootStore

	indexes, err := f.users.GetIndexes(f.ctx)
	require.NoError(t, err)

	require.Equal(t, 1, len(indexes))
	assert.Equal(t, testUsersColIndexName, indexes[0].Name)
}

func TestCollectionGetIndexes_IfInvalidIndexIsStored_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()
	f.createUserCollectionIndexOnAge()

	indexes, err := f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	require.Len(t, indexes, 2)
	require.ElementsMatch(t,
		[]string{testUsersColIndexName, testUsersColIndexAge},
		[]string{indexes[0].Name, indexes[1].Name},
	)
	require.ElementsMatch(t, []uint32{1, 2}, []uint32{indexes[0].ID, indexes[1].ID})
}

func TestCollectionGetIndexes_IfIndexIsCreated_ShouldUpdateCache(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	indexes, err := f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	assert.Len(t, indexes, 1)

	_, err = f.users.CreateIndex(f.ctx, getUsersIndexDescOnAge())
	assert.NoError(t, err)

	indexes, err = f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	assert.Len(t, indexes, 2)
}

func TestCollectionGetIndexes_IfIndexIsDropped_ShouldUpdateCache(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()
	f.createUserCollectionIndexOnAge()

	indexes, err := f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	assert.Len(t, indexes, 2)

	err = f.users.DropIndex(f.ctx, testUsersColIndexName)
	assert.NoError(t, err)

	indexes, err = f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	assert.Len(t, indexes, 1)
	assert.Equal(t, indexes[0].Name, testUsersColIndexAge)

	err = f.users.DropIndex(f.ctx, testUsersColIndexAge)
	assert.NoError(t, err)

	indexes, err = f.users.GetIndexes(f.ctx)
	assert.NoError(t, err)
	assert.Len(t, indexes, 0)
}

func TestDropIndex_ShouldDeleteIndex(t *testing.T) {
	f := newIndexTestFixture(t)
	desc := f.createUserCollectionIndexOnName()

	err := f.dropIndex(usersColName, desc.Name)
	assert.NoError(t, err)

	indexKey := core.NewCollectionIndexKey(usersColName, desc.Name)
	_, err = f.txn.Systemstore().Get(f.ctx, indexKey.ToDS())
	assert.Error(t, err)
}

func TestDropIndex_IfStorageFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)
	desc := f.createUserCollectionIndexOnName()

	f.db.Close(f.ctx)

	err := f.dropIndex(productsColName, desc.Name)
	assert.Error(t, err)
}

func TestDropIndex_IfCollectionDoesntExist_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)

	err := f.dropIndex(productsColName, "any_name")
	assert.ErrorIs(t, err, NewErrCollectionDoesntExist(usersColName))
}

func TestDropIndex_IfFailsToQuerySystemStorage_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)
	desc := f.createUserCollectionIndexOnName()

	testErr := errors.New("test error")

	mockTxn := f.mockTxn().ClearSystemStore()
	systemStoreOn := mockTxn.MockSystemstore.EXPECT()
	systemStoreOn.Query(mock.Anything, mock.Anything).Return(nil, testErr)
	f.stubSystemStore(systemStoreOn)

	err := f.dropIndex(usersColName, desc.Name)
	require.ErrorIs(t, err, testErr)
}

func TestDropIndex_IfFailsToCreateTxn_ShouldNotCache(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	testErr := errors.New("test error")

	mockedRootStore := mocks.NewRootStore(t)
	mockedRootStore.EXPECT().NewTransaction(mock.Anything, mock.Anything).Return(nil, testErr)
	f.db.rootstore = mockedRootStore

	err := f.users.DropIndex(f.ctx, testUsersColIndexName)
	require.ErrorIs(t, err, testErr)
}

func TestDropIndex_IfFailsToDeleteFromStorage_ShouldNotCache(t *testing.T) {
	f := newIndexTestFixture(t)

	f.createUserCollectionIndexOnName()

	testErr := errors.New("test error")

	mockedTxn := f.mockTxn().ClearSystemStore()
	systemStoreOn := mockedTxn.MockSystemstore.EXPECT()
	systemStoreOn.Delete(mock.Anything, mock.Anything).Return(testErr)
	f.stubSystemStore(systemStoreOn)
	mockedTxn.MockDatastore.EXPECT().Query(mock.Anything, mock.Anything).Maybe().
		Return(mocks.NewQueryResultsWithValues(t), nil)

	err := f.users.WithTxn(mockedTxn).DropIndex(f.ctx, testUsersColIndexName)
	require.ErrorIs(t, err, testErr)
}

func TestDropAllIndex_ShouldDeleteAllIndexes(t *testing.T) {
	f := newIndexTestFixture(t)
	_, err := f.createCollectionIndexFor(usersColName, client.IndexDescription{
		Fields: []client.IndexedFieldDescription{
			{Name: usersNameFieldName, Direction: client.Ascending},
		},
	})
	assert.NoError(f.t, err)

	_, err = f.createCollectionIndexFor(usersColName, client.IndexDescription{
		Fields: []client.IndexedFieldDescription{
			{Name: usersAgeFieldName, Direction: client.Ascending},
		},
	})
	assert.NoError(f.t, err)

	assert.Equal(t, 2, f.countIndexPrefixes(usersColName, ""))

	err = f.dropAllIndexes(usersColName)
	assert.NoError(t, err)

	assert.Equal(t, 0, f.countIndexPrefixes(usersColName, ""))
}

func TestDropAllIndexes_IfStorageFails_ReturnError(t *testing.T) {
	f := newIndexTestFixture(t)
	f.createUserCollectionIndexOnName()

	f.db.Close(f.ctx)

	err := f.dropAllIndexes(usersColName)
	assert.Error(t, err)
}
