// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package query

import (
	"testing"

	"github.com/lens-vm/lens/host-go/config/model"

	"github.com/sourcenetwork/defradb/client"
	testUtils "github.com/sourcenetwork/defradb/tests/integration"
	"github.com/sourcenetwork/defradb/tests/lenses"
)

func TestSchemaMigrationQuery(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMultipleDocs(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, multiple documents",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "Islam"
				}`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "Fred"
				}`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "Shahzad"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "Islam",
						"verified": true,
					},
					{
						"name":     "Fred",
						"verified": true,
					},
					{
						"name":     "Shahzad",
						"verified": true,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

// Users may want to register migrations before the schema is locally updated. This may be particularly useful
// for downgrading documents recieved via P2P.
func TestSchemaMigrationQueryWithMigrationRegisteredBeforeSchemaPatch(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration set before schema updated",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigratesToIntermediaryVersion(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, to intermediary version",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": "String"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				// Register a migration from schema version 1 to schema version 2 **only** -
				// there should be no migration from version 2 to version 3.
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
						email
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
						"email":    nil,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigratesFromIntermediaryVersion(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, from intermediary version",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": "String"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				// Register a migration from schema version 2 to schema version 3 **only** -
				// there should be no migration from version 1 to version 2.
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					DestinationSchemaVersionID: "bafkreihv4ktjwzyhhkmas5iz4q7cawet4aeurqci33i66wr225l5pet4qu",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
						email
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
						"email":    nil,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigratesAcrossMultipleVersions(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, across multiple migrated versions",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": "String"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					DestinationSchemaVersionID: "bafkreihv4ktjwzyhhkmas5iz4q7cawet4aeurqci33i66wr225l5pet4qu",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "email",
									"value": "ilovewasm@source.com",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
						email
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
						"email":    "ilovewasm@source.com",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigratesAcrossMultipleVersionsBeforePatches(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, multiple migrations before patch",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					DestinationSchemaVersionID: "bafkreihv4ktjwzyhhkmas5iz4q7cawet4aeurqci33i66wr225l5pet4qu",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "email",
									"value": "ilovewasm@source.com",
								},
							},
						},
					},
				},
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": "String"} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
						email
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
						"email":    "ilovewasm@source.com",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigratesAcrossMultipleVersionsBeforePatchesWrongOrder(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, multiple migrations before patch",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.ConfigureMigration{
				// Declare the migration from v2=>v3 before declaring the migration from v1=>v2
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					DestinationSchemaVersionID: "bafkreihv4ktjwzyhhkmas5iz4q7cawet4aeurqci33i66wr225l5pet4qu",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "email",
									"value": "ilovewasm@source.com",
								},
							},
						},
					},
				},
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "email", "Kind": "String"} }
					]
				`,
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
						email
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": true,
						"email":    "ilovewasm@source.com",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

// This test is important as it tests that orphan migrations do not block the fetcher(s)
// from functioning.
//
// It is important to allow these orphans to be persisted as they may later become linked to the
// schema version history chain as either new migrations are added or the local schema is updated
// bridging the gap.
func TestSchemaMigrationQueryWithUnknownSchemaMigration(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "not a schema version",
					DestinationSchemaVersionID: "also not a schema version",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "verified",
									"value": true,
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						verified
					}
				}`,
				Results: []map[string]any{
					{
						"name":     "John",
						"verified": nil,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationMutatesExistingScalarField(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration mutating existing scalar field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John"
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreibjb4h5nudsei7cq2kkontjinmjpbqls2tmowqp5nxougu4tuus4i",
					DestinationSchemaVersionID: "bafkreih6o2jyurelxtpbg66gk23pio2tq6o3aed334z6w2u3qwve3at7ku",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								// This may appear to be an odd thing to do, but it is just a simplification.
								// Existing fields may be mutated by migrations, and that is what we are testing
								// here.
								Arguments: map[string]any{
									"dst":   "name",
									"value": "Fred",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
					}
				}`,
				Results: []map[string]any{
					{
						"name": "Fred",
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationMutatesExistingInlineArrayField(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration mutating existing inline-array field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						mobile: [Int!]
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"mobile": [644, 832, 8325]
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreic2fcxa2e7o2acur6yh6iv7vyso4ecgfcqbbp6l55twpgdumdctui",
					DestinationSchemaVersionID: "bafkreidz6fo522l4vzsdbe4b5mhm3c7tc5xmve7i2egsk4s53zg6emkbyy",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								// This may appear to be an odd thing to do, but it is just a simplification.
								// Existing fields may be mutated by migrations, and that is what we are testing
								// here.
								Arguments: map[string]any{
									"dst":   "mobile",
									"value": []int{847, 723, 2012},
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						mobile
					}
				}`,
				Results: []map[string]any{
					{
						"mobile": []int64{847, 723, 2012},
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationRemovesExistingField(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration removing existing field",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John",
					"age": 40
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreihh4zkyuqk4ibwb5utyayvbw75hdfkueg3scm7taysk3rbh2jhaee",
					DestinationSchemaVersionID: "bafkreifzcnwsq2os36utxnqpmq74wjt7o2czkcjo6exzv4fhm3ni2ounxe",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.RemoveModulePath,
								Arguments: map[string]any{
									"target": "age",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						age
					}
				}`,
				Results: []map[string]any{
					{
						"name": "John",
						"age":  nil,
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationPreservesExistingFieldWhenFieldNotRequested(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration preserves existing field without requesting it",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John",
					"age": 40
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "verified", "Kind": "Boolean"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreihh4zkyuqk4ibwb5utyayvbw75hdfkueg3scm7taysk3rbh2jhaee",
					DestinationSchemaVersionID: "bafkreifzcnwsq2os36utxnqpmq74wjt7o2czkcjo6exzv4fhm3ni2ounxe",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.SetDefaultModulePath,
								Arguments: map[string]any{
									"dst":   "name",
									"value": "Fred",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
					}
				}`,
				Results: []map[string]any{
					{
						"name": "Fred",
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						age
					}
				}`,
				Results: []map[string]any{
					{
						"name": "Fred",
						"age":  int64(40),
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationCopiesExistingFieldWhenSrcFieldNotRequested(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration copies existing field without requesting src",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John",
					"age": 40
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "yearsLived", "Kind": "Int"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreihh4zkyuqk4ibwb5utyayvbw75hdfkueg3scm7taysk3rbh2jhaee",
					DestinationSchemaVersionID: "bafkreica72aah4lm4sry67eqxqufsr24to6abgocomra4qeokwa7oaazwi",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.CopyModulePath,
								Arguments: map[string]any{
									"src": "age",
									"dst": "yearsLived",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						yearsLived
					}
				}`,
				Results: []map[string]any{
					{
						"name":       "John",
						"yearsLived": int64(40),
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}

func TestSchemaMigrationQueryMigrationCopiesExistingFieldWhenSrcAndDstFieldNotRequested(t *testing.T) {
	test := testUtils.TestCase{
		Description: "Test schema migration, migration copies existing field without requesting src or dst",
		Actions: []any{
			testUtils.SchemaUpdate{
				Schema: `
					type Users {
						name: String
						age: Int
					}
				`,
			},
			testUtils.CreateDoc{
				Doc: `{
					"name": "John",
					"age": 40
				}`,
			},
			testUtils.SchemaPatch{
				Patch: `
					[
						{ "op": "add", "path": "/Users/Fields/-", "value": {"Name": "yearsLived", "Kind": "Int"} }
					]
				`,
			},
			testUtils.ConfigureMigration{
				LensConfig: client.LensConfig{
					SourceSchemaVersionID:      "bafkreihh4zkyuqk4ibwb5utyayvbw75hdfkueg3scm7taysk3rbh2jhaee",
					DestinationSchemaVersionID: "bafkreica72aah4lm4sry67eqxqufsr24to6abgocomra4qeokwa7oaazwi",
					Lens: model.Lens{
						Lenses: []model.LensModule{
							{
								Path: lenses.CopyModulePath,
								Arguments: map[string]any{
									"src": "age",
									"dst": "yearsLived",
								},
							},
						},
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
					}
				}`,
				Results: []map[string]any{
					{
						"name": "John",
					},
				},
			},
			testUtils.Request{
				Request: `query {
					Users {
						name
						age
						yearsLived
					}
				}`,
				Results: []map[string]any{
					{
						"name":       "John",
						"age":        int64(40),
						"yearsLived": int64(40),
					},
				},
			},
		},
	}

	testUtils.ExecuteTestCase(t, test)
}
