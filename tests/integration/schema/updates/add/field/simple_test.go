// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package field

import (
	"testing"

	"github.com/sourcenetwork/immutable"

	"github.com/sourcenetwork/defradb/client"
	testUtils "github.com/sourcenetwork/defradb/tests/integration"
)

func TestSchemaUpdatesAddFieldSimple(t *testing.T) {
	schemaVersion1ID := "bafkreig3zt63qt7bkji47etyu2sqtzroa3tcfdxgwqc3ka2ijy63refq3a"
	schemaVersion2ID := "bafkreiclwd4nrvczrzy7aj52olojyzvgm4ht6jpktwpxuqej5wk3ocxpqi"

	test := testUtils.TestCase{
		Description: "Test schema update, add field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						email
					}
				}`,
				Results: []map[string]any{},
			},
			testUtils.GetSchema{
				VersionID: immutable.Some(schemaVersion2ID),
				ExpectedResults: []client.SchemaDescription{
					{
						Name:      "Users",
						VersionID: schemaVersion2ID,
						Root:      schemaVersion1ID,
						Fields: []client.FieldDescription{
							{
								Name: "_docID",
								Kind: client.FieldKind_DocID,
								Typ:  client.LWW_REGISTER,
							},
							{
								Name: "name",
								ID:   1,
								Kind: client.FieldKind_STRING,
								Typ:  client.LWW_REGISTER,
							},
							{
								Name: "email",
								ID:   2,
								Kind: client.FieldKind_STRING,
								Typ:  client.LWW_REGISTER,
							},
						},
					},
				},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdates_AddFieldSimpleDoNotSetDefault_Errors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
				SetAsDefaultVersion: immutable.Some(false),
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						email
					}
				}`,
				ExpectedError: `Cannot query field "email" on type "Users".`,
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdates_AddFieldSimpleDoNotSetDefault_VersionIsQueryable(t *testing.T) {
	schemaVersion1ID := "bafkreig3zt63qt7bkji47etyu2sqtzroa3tcfdxgwqc3ka2ijy63refq3a"
	schemaVersion2ID := "bafkreiclwd4nrvczrzy7aj52olojyzvgm4ht6jpktwpxuqej5wk3ocxpqi"

	test := testUtils.TestCase{
		Description: "Test schema update, add field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
				SetAsDefaultVersion: immutable.Some(false),
			},
			testUtils.GetSchema{
				VersionID: immutable.Some(schemaVersion2ID),
				ExpectedResults: []client.SchemaDescription{
					{
						Name: "Users",
						// Even though schema version 2 is not active, it should still be possible to
						// fetch it.
						VersionID: schemaVersion2ID,
						Root:      schemaVersion1ID,
						Fields: []client.FieldDescription{
							{
								Name: "_docID",
								Kind: client.FieldKind_DocID,
								Typ:  client.LWW_REGISTER,
							},
							{
								Name: "name",
								ID:   1,
								Kind: client.FieldKind_STRING,
								Typ:  client.LWW_REGISTER,
							},
							{
								Name: "email",
								ID:   2,
								Kind: client.FieldKind_STRING,
								Typ:  client.LWW_REGISTER,
							},
						},
					},
				},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldSimpleErrorsAddingToUnknownCollection(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add to unknown collection fails",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Authors/Schema/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
				ExpectedError: "add operation does not apply: doc is missing path",
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
					}
				}`,
				Results: []map[string]any{},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldMultipleInPatch(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add multiple fields in single patch",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} },
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "city", "Kind": 11} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						email
						city
					}
				}`,
				Results: []map[string]any{},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldMultiplePatches(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add multiple patches",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "city", "Kind": 11} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						email
						city
					}
				}`,
				Results: []map[string]any{},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldSimpleWithoutName(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add field without name",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Kind": 11} }
					]
				`,
				ExpectedError: "Names must match /^[_a-zA-Z][_a-zA-Z0-9]*$/ but \"\" does not.",
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldMultipleInPatchPartialSuccess(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add multiple fields in single patch with rollback",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				// Email field is valid, City field has invalid kind
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} },
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "city", "Kind": 111} }
					]
				`,
				ExpectedError: "no type found for given name. Type: 111",
			},
			testUtils.Request{
				// Email does not exist as the commit failed
				Request: `query {
					Users {
						name
						email
					}
				}`,
				ExpectedError: "Cannot query field \"email\" on type \"Users\"",
			},
			testUtils.Request{
				// Original schema is preserved
				Request: `query {
					Users {
						name
					}
				}`,
				Results: []map[string]any{},
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldSimpleDuplicateOfExistingField(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add field that already exists",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "name", "Kind": 11} }
					]
				`,
				ExpectedError: "duplicate field. Name: name",
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldSimpleDuplicateField(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add duplicate fields",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} },
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": 11} }
					]
				`,
				ExpectedError: "duplicate field. Name: email",
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaUpdatesAddFieldWithExplicitIDErrors(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema update, add field that already exists",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"ID": 2, "Name": "email", "Kind": 11} }
					]
				`,
				ExpectedError: "explicitly setting a field ID value is not supported. Field: email, ID: 2",
			},
		},
	}
	testUtils.ExecuteTestCase(t, test)
}
