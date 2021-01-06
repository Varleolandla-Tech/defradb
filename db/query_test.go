package db

import (
	"fmt"
	"testing"

	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/document"
	"github.com/sourcenetwork/defradb/query/graphql/planner"
	"github.com/stretchr/testify/assert"
)

// var userCollectionGQLSchema = (`
// type users {
// 	Name: String
// 	Age: Int
// }
// `)

// // func newQueryableDB()

// func TestSimpleCollectionQuery(t *testing.T) {
// 	db, err := newMemoryDB()
// 	assert.NoError(t, err)

// 	desc := newTestCollectionDescription()
// 	col, err := db.CreateCollection(desc)
// 	assert.NoError(t, err)

// 	executor, err := planner.NewQueryExecutor()
// 	assert.NoError(t, err)

// 	err = executor.Generator.FromSDL(userCollectionGQLSchema)
// 	assert.NoError(t, err)

// 	doc1, err := document.NewFromJSON([]byte(`{
// 		"Name": "John",
// 		"Age": 21
// 	}`))

// 	assert.NoError(t, err)
// 	err = col.Save(doc1)
// 	assert.NoError(t, err)

// 	txn, err := db.NewTxn(true)
// 	assert.NoError(t, err)

// 	// obj := executor.SchemaManager.Schema().TypeMap()["users"].(*gql.Object)
// 	// obj.Fields()
// 	// spew.Dump(obj.Fields())

// 	var userQuery = (`
// 	query {
// 		users {
// 			Name
// 			Age
// 		}
// 	}`)

// 	docs, err := executor.ExecQuery(txn, userQuery)
// 	assert.NoError(t, err)

// 	fmt.Println(docs)
// 	assert.True(t, len(docs) == 1)
// }

// func TestSimpleCollectionQueryWithFilter(t *testing.T) {
// 	db, err := newMemoryDB()
// 	assert.NoError(t, err)

// 	desc := newTestCollectionDescription()
// 	col, err := db.CreateCollection(desc)
// 	assert.NoError(t, err)

// 	executor, err := planner.NewQueryExecutor()
// 	assert.NoError(t, err)

// 	err = executor.Generator.FromSDL(userCollectionGQLSchema)
// 	assert.NoError(t, err)

// 	doc1, err := document.NewFromJSON([]byte(`{
// 		"Name": "John",
// 		"Age": 21
// 	}`))

// 	assert.NoError(t, err)
// 	err = col.Save(doc1)
// 	assert.NoError(t, err)

// 	txn, err := db.NewTxn(true)
// 	assert.NoError(t, err)

// 	// obj := executor.SchemaManager.Schema().TypeMap()["users"].(*gql.Object)
// 	// obj.Fields()
// 	// spew.Dump(obj.Fields())

// 	var userQuery = (`
// 	query {
// 		users(filter: {Name: {_eq: "John"}}) {
// 			Name
// 			Age
// 		}
// 	}`)

// 	docs, err := executor.ExecQuery(txn, userQuery)
// 	assert.NoError(t, err)

// 	// fmt.Println(docs)
// 	assert.Len(t, docs, 1)

// 	assert.Equal(t, map[string]interface{}{
// 		"Name": "John",
// 		"Age":  uint64(21),
// 	}, docs[0])
// }

func newTestQueryCollectionDescription1() base.CollectionDescription {
	return base.CollectionDescription{
		Name: "users",
		ID:   uint32(1),
		Schema: base.SchemaDescription{
			ID:       uint32(1),
			FieldIDs: []uint32{1, 2, 3, 5},
			Fields: []base.FieldDescription{
				base.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				base.FieldDescription{
					Name: "Name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "Age",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_INT,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "Verified",
					ID:   base.FieldID(4),
					Kind: base.FieldKind_BOOL,
					Typ:  core.LWW_REGISTER,
				},
			},
		},
		Indexes: []base.IndexDescription{
			base.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}
}

func newTestQueryCollectionDescription2() base.CollectionDescription {
	return base.CollectionDescription{
		Name: "book",
		ID:   uint32(2),
		Schema: base.SchemaDescription{
			ID:       uint32(2),
			FieldIDs: []uint32{1, 2, 3, 4, 5},
			Fields: []base.FieldDescription{
				base.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				base.FieldDescription{
					Name: "name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "rating",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_FLOAT,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name:   "author",
					ID:     base.FieldID(5),
					Kind:   base.FieldKind_FOREIGN_OBJECT,
					Schema: "author",
					Typ:    core.NONE_CRDT,
					Meta:   base.Meta_Relation_ONE | base.Meta_Relation_Primary,
				},
				base.FieldDescription{
					Name: "author_id",
					ID:   base.FieldID(6),
					Kind: base.FieldKind_DocKey,
					Typ:  core.LWW_REGISTER,
				},
			},
		},
		Indexes: []base.IndexDescription{
			base.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}
}

func newTestQueryCollectionDescription3() base.CollectionDescription {
	return base.CollectionDescription{
		Name: "author",
		ID:   uint32(3),
		Schema: base.SchemaDescription{
			ID:       uint32(3),
			Name:     "author",
			FieldIDs: []uint32{1, 2, 3, 4, 5, 6},
			Fields: []base.FieldDescription{
				base.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				base.FieldDescription{
					Name: "name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "age",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_INT,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "verified",
					ID:   base.FieldID(4),
					Kind: base.FieldKind_BOOL,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name:   "published",
					ID:     base.FieldID(5),
					Kind:   base.FieldKind_FOREIGN_OBJECT,
					Schema: "book",
					Typ:    core.NONE_CRDT,
					Meta:   base.Meta_Relation_ONE,
				},
				base.FieldDescription{
					Name: "published_id",
					ID:   base.FieldID(6),
					Kind: base.FieldKind_DocKey,
					Typ:  core.LWW_REGISTER,
				},
			},
		},
		Indexes: []base.IndexDescription{
			base.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}
}

func newTestQueryCollectionDescription4() base.CollectionDescription {
	return base.CollectionDescription{
		Name: "author",
		ID:   uint32(3),
		Schema: base.SchemaDescription{
			ID:       uint32(3),
			Name:     "author",
			FieldIDs: []uint32{1, 2, 3, 4, 5},
			Fields: []base.FieldDescription{
				base.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				base.FieldDescription{
					Name: "name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "age",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_INT,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name: "verified",
					ID:   base.FieldID(4),
					Kind: base.FieldKind_BOOL,
					Typ:  core.LWW_REGISTER,
				},
				base.FieldDescription{
					Name:   "published",
					ID:     base.FieldID(5),
					Kind:   base.FieldKind_FOREIGN_OBJECT_ARRAY,
					Schema: "book",
					Typ:    core.NONE_CRDT,
					Meta:   base.Meta_Relation_ONEMANY,
				},
			},
		},
		Indexes: []base.IndexDescription{
			base.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}
}

type queryTestCase struct {
	description string
	query       string
	docs        map[int][]string
	results     []map[string]interface{}
}

func TestQuerySimple(t *testing.T) {
	var userCollectionGQLSchema = (`
	type users {
		Name: String
		Age: Int
		Verified: Boolean
	}
	`)

	tests := []queryTestCase{
		{
			description: "Simple query with no filter",
			query: `query {
						users {
							_key
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"_key": "bae-52b9170d-b77a-5887-b877-cbdbb99b009f",
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with alias, no filter",
			query: `query {
						users {
							username: Name
							age: Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"username": "John",
					"age":      uint64(21),
				},
			},
		},
		{
			description: "Simple query with no filter, mutiple rows",
			query: `query {
						users {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 27
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Bob",
					"Age":  uint64(27),
				},
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter (key)",
			query: `query {
						users(filter: {_key: {_eq: "bae-52b9170d-b77a-5887-b877-cbdbb99b009f"}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter (Name)",
			query: `query {
						users(filter: {Name: {_eq: "John"}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter and selection",
			query: `query {
						users(filter: {Name: {_eq: "John"}}) {
							Name					
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
				},
			},
		},
		{
			description: "Simple query with basic filter and selection (diff from filter)",
			query: `query {
						users(filter: {Name: {_eq: "John"}}) {
							Age					
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Age": uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter(name), no results",
			query: `query {
						users(filter: {Name: {_eq: "Bob"}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{},
		},
		{
			description: "Simple query with basic filter(age)",
			query: `query {
						users(filter: {Age: {_eq: 21}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter(age), greater than",
			query: `query {
						users(filter: {Age: {_gt: 20}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic filter(age)",
			query: `query {
						users(filter: {Age: {_gt: 40}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`)},
			},
			results: []map[string]interface{}{},
		},
		{
			description: "Simple query with basic filter(age)",
			query: `query {
						users(filter: {Age: {_gt: 20}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic limit",
			query: `query {
						users(limit: 1) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				// {
				// 	"Name": "John",
				// 	"Age":  uint64(21),
				// },
			},
		},
		{
			description: "Simple query with basic limit & offset",
			query: `query {
						users(limit: 1, offset: 1) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`)},
			},
			results: []map[string]interface{}{
				// {
				// 	"Name": "Bob",
				// 	"Age":  uint64(32),
				// },
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with basic limit, more rows",
			query: `query {
						users(limit: 2) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				{
					"Name": "Alice",
					"Age":  uint64(19),
				},
			},
		},
		{
			description: "Simple query with basic limit & offset, more rows",
			query: `query {
						users(limit: 2, offset: 2) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "John",
					"Age":  uint64(21),
				},
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
			},
		},
		{
			description: "Simple query with basic sort ASC",
			query: `query {
						users(order: {Age: ASC}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Alice",
					"Age":  uint64(19),
				},
				{
					"Name": "John",
					"Age":  uint64(21),
				},
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
			},
		},
		{
			description: "Simple query with basic sort DESC",
			query: `query {
						users(order: {Age: DESC}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				{
					"Name": "John",
					"Age":  uint64(21),
				},
				{
					"Name": "Alice",
					"Age":  uint64(19),
				},
			},
		},
		{
			description: "Simple query with compound sort",
			query: `query {
						users(order: {Age: DESC, Verified: ASC}) {
							Name
							Age
							Verified
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21,
					"Verified": true
				}`),
					(`{
					"Name": "Bob",
					"Age": 21,
					"Verified": false
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55,
					"Verified": true
				}`),
					(`{
					"Name": "Alice",
					"Age": 19,
					"Verified": false
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name":     "Carlo",
					"Age":      uint64(55),
					"Verified": true,
				},
				{
					"Name":     "Bob",
					"Age":      uint64(21),
					"Verified": false,
				},
				{
					"Name":     "John",
					"Age":      uint64(21),
					"Verified": true,
				},
				{
					"Name":     "Alice",
					"Age":      uint64(19),
					"Verified": false,
				},
			},
		},
		{
			description: "Simple query with sort & filter",
			query: `query {
						users(filter: {Age: {_gt: 30}}, order: {Age: DESC}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
			},
		},
		{
			description: "Simple query with logical compound filter (and)",
			query: `query {
						users(filter: {_and: [{Age: {_gt: 20}}, {Age: {_lt: 50}}]}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Bob",
					"Age":  uint64(32),
				},
				{
					"Name": "John",
					"Age":  uint64(21),
				},
			},
		},
		{
			description: "Simple query with logical compound filter (or)",
			query: `query {
						users(filter: {_or: [{Age: {_eq: 55}}, {Age: {_eq: 19}}]}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Alice",
					"Age":  uint64(19),
				},
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
			},
		},
		{
			description: "Simple query with special filter (or)",
			query: `query {
						users(filter: {Age: {_in: [19, 40, 55]}}) {
							Name
							Age
						}
					}`,
			docs: map[int][]string{
				0: []string{
					(`{
					"Name": "John",
					"Age": 21
				}`),
					(`{
					"Name": "Bob",
					"Age": 32
				}`),
					(`{
					"Name": "Carlo",
					"Age": 55
				}`),
					(`{
					"Name": "Alice",
					"Age": 19
				}`)},
			},
			results: []map[string]interface{}{
				{
					"Name": "Alice",
					"Age":  uint64(19),
				},
				{
					"Name": "Carlo",
					"Age":  uint64(55),
				},
			},
		},
	}

	for _, test := range tests {
		db, err := newMemoryDB()
		assert.NoError(t, err)

		desc := newTestQueryCollectionDescription1()
		col, err := db.CreateCollection(desc)
		assert.NoError(t, err)

		executor, err := planner.NewQueryExecutor()
		assert.NoError(t, err)

		db.queryExecutor = executor

		err = executor.Generator.FromSDL(userCollectionGQLSchema)
		assert.NoError(t, err)
		runQueryTestCase(t, []*Collection{col}, test)
	}

}

func TestQueryRelationOne(t *testing.T) {
	var bookAuthorGQLSchema = (`
	type book {
		name: String
		rating: Float
		author: author @primary
	}

	type author {
		name: String
		age: Int
		verified: Boolean
		published: book
	}
	`)

	tests := []queryTestCase{
		{
			description: "One-to-one relation query with no filter",
			query: `query {
						book {
							name
							rating
							author {
								name
								age
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			description: "One-to-one relation query with simple filter on sub type",
			query: `query {
						book {
							name
							rating
							author(filter: {age: {_eq: 65}}) {
								name
								age
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			description: "One-to-one relation query with simple filter on parent",
			query: `query {
						book(filter: {name: {_eq: "Painted House"}}) {
							name
							rating
							author {
								name
								age
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			description: "One-to-one relation query with simple sub filter on parent",
			query: `query {
						book(filter: {author: {verified: {_eq: true}}}) {
							name
							rating
							author {
								name
								age
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			description: "One-to-one relation query with simple sort by sub type",
			query: `query {
				book(order: {author: {verified: DESC}}) {
					name
					rating
					author {
						name
						age
					}
				}
			}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
					(`{
					"name": "Theif Lord",
					"rating": 4.8,
					"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
					}`),
				},
				//authors
				1: []string{
					// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{ 
					"name": "John Grisham",
					"age": 65,
					"verified": true
					}`),
					// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
					(`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
					}`),
				},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
				{
					"name":   "Theif Lord",
					"rating": 4.8,
					"author": map[string]interface{}{
						"name": "Cornelia Funke",
						"age":  uint64(62),
					},
				},
			},
		},
		{
			description: "One-to-one relation secondary direction, no filter",
			query: `query {
						author {
							name
							age
							published {
								name
								rating
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name": "John Grisham",
					"age":  uint64(65),
					"published": map[string]interface{}{
						"name":   "Painted House",
						"rating": 4.9,
					},
				},
			},
		},
	}

	for _, test := range tests {
		db, err := newMemoryDB()
		assert.NoError(t, err)

		bookDesc := newTestQueryCollectionDescription2()
		bookCol, err := db.CreateCollection(bookDesc)
		assert.NoError(t, err)

		authorDesc := newTestQueryCollectionDescription3()
		authorCol, err := db.CreateCollection(authorDesc)
		assert.NoError(t, err)

		executor, err := planner.NewQueryExecutor()
		assert.NoError(t, err)

		db.queryExecutor = executor

		err = executor.Generator.FromSDL(bookAuthorGQLSchema)
		assert.NoError(t, err)
		runQueryTestCase(t, []*Collection{bookCol, authorCol}, test)
	}

}

func TestQueryRelationMany(t *testing.T) {
	var bookAuthorGQLSchema = (`
	type book {
		name: String
		rating: Float
		author: author
	}

	type author {
		name: String
		age: Int
		verified: Boolean
		published: [book]
	}
	`)

	tests := []queryTestCase{
		{
			description: "One-to-many relation query from one side",
			query: `query {
						book {
							name
							rating
							author {
								name
								age
							}
						}
					}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
					"name": "Painted House",
					"rating": 4.9,
					"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
				}`)},
				//authors
				1: []string{ // bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{
					"name": "John Grisham",
					"age": 65,
					"verified": true
				}`)},
			},
			results: []map[string]interface{}{
				{
					"name":   "Painted House",
					"rating": 4.9,
					"author": map[string]interface{}{
						"name": "John Grisham",
						"age":  uint64(65),
					},
				},
			},
		},
		{
			description: "One-to-many relation query from many side",
			query: `query {
				author {
					name
					age
					published {
						name
						rating
					}
				}
			}`,
			docs: map[int][]string{
				//books
				0: []string{ // bae-fd541c25-229e-5280-b44b-e5c2af3e374d
					(`{
						"name": "Painted House",
						"rating": 4.9,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
					}`),
					(`{
						"name": "A Time for Mercy",
						"rating": 4.5,
						"author_id": "bae-41598f0c-19bc-5da6-813b-e80f14a10df3"
						}`),
					(`{
						"name": "Theif Lord",
						"rating": 4.8,
						"author_id": "bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04"
					}`),
				},
				//authors
				1: []string{
					// bae-41598f0c-19bc-5da6-813b-e80f14a10df3
					(`{ 
					"name": "John Grisham",
					"age": 65,
					"verified": true
					}`),
					// bae-b769708d-f552-5c3d-a402-ccfd7ac7fb04
					(`{
					"name": "Cornelia Funke",
					"age": 62,
					"verified": false
					}`),
				},
			},
			results: []map[string]interface{}{
				{
					"name": "John Grisham",
					"age":  uint64(65),
					"published": []map[string]interface{}{
						{
							"name":   "Painted House",
							"rating": 4.9,
						},
						{
							"name":   "A Time for Mercy",
							"rating": 4.5,
						},
					},
				},
				{
					"name": "Cornelia Funke",
					"age":  uint64(62),
					"published": []map[string]interface{}{
						{
							"name":   "Theif Lord",
							"rating": 4.8,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		db, err := newMemoryDB()
		assert.NoError(t, err)

		bookDesc := newTestQueryCollectionDescription2()
		bookCol, err := db.CreateCollection(bookDesc)
		assert.NoError(t, err)

		authorDesc := newTestQueryCollectionDescription4()
		authorCol, err := db.CreateCollection(authorDesc)
		assert.NoError(t, err)

		executor, err := planner.NewQueryExecutor()
		assert.NoError(t, err)

		db.queryExecutor = executor

		err = executor.Generator.FromSDL(bookAuthorGQLSchema)
		assert.NoError(t, err)
		runQueryTestCase(t, []*Collection{bookCol, authorCol}, test)
	}
}

func runQueryTestCase(t *testing.T, collections []*Collection, test queryTestCase) {
	// insert docs
	for cid, docs := range test.docs {
		for _, docStr := range docs {
			doc, err := document.NewFromJSON([]byte(docStr))
			assert.NoError(t, err, test.description)
			collections[cid].Save(doc)
		}
	}

	// exec query
	db := collections[0].db
	txn, err := db.NewTxn(true)
	assert.NoError(t, err, test.description)
	results, err := db.queryExecutor.ExecQuery(txn, test.query)
	assert.NoError(t, err, test.description)

	fmt.Println(test.description)
	fmt.Println(results)
	fmt.Println("--------------")
	fmt.Println("")

	// compare results
	assert.Equal(t, len(test.results), len(results), test.description)
	for i, result := range results {
		assert.Equal(t, test.results[i], result, test.description)
	}
}
