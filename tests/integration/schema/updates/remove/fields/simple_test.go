// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package fields

import (
	"testing"

	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestSchemaUpdatesRemoveFieldErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields/2" }
					]
				`,
				ExpectedError: "deleting an existing field is not supported. Name: Name",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveAllFieldsErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove all fields",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields" }
					]
				`,
				ExpectedError: "deleting an existing field is not supported",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveFieldNameErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field name",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields/2/Name" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 2, ProposedName: ",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveFieldIDErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field id",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields/2/ID" }
					]
				`,
				ExpectedError: "deleting an existing field is not supported. Name: Name, ID: 2",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveFieldKindErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field kind",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields/2/Kind" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 2, ProposedName: ",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveFieldTypErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field Typ",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						Name: String
						Email: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Users/Schema/Fields/2/Typ" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 2, ProposedName: ",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Users"}, test)
}

func TestSchemaUpdatesRemoveFieldSchemaErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field Schema",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Author {
						Name: String
						Book: [Book]
					}
					type Book {
						Name: String
						Author: [Author]
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Author/Schema/Fields/1/Schema" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 1, ProposedName: Book",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Author", "Book"}, test)
}

func TestSchemaUpdatesRemoveFieldRelationNameErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field RelationName",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Author {
						Name: String
						Book: [Book]
					}
					type Book {
						Name: String
						Author: [Author]
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Author/Schema/Fields/1/RelationName" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 1, ProposedName: Book",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Author", "Book"}, test)
}

func TestSchemaUpdatesRemoveFieldRelationTypeErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, remove field RelationType",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Author {
						Name: String
						Book: [Book]
					}
					type Book {
						Name: String
						Author: [Author]
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "remove", "path": "/Author/Schema/Fields/1/RelationType" }
					]
				`,
				ExpectedError: "mutating an existing field is not supported. ID: 1, ProposedName: Book",
			},
		},
	}
	testUtils.ExecuteTestCase(t, []string{"Author", "Book"}, test)
}
