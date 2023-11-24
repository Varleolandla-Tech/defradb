// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package gen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sourcenetwork/defradb/client"
)

func TestGeneratePredefinedFromSchema_Simple(t *testing.T) {
	schema := `
		type User {
			name: String
			age: Int
		}`

	docsList := DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{"name": "John", "age": 30},
			{"name": "Fred", "age": 25},
		},
	}
	docs, err := GeneratePredefinedFromSDL(schema, docsList)
	assert.NoError(t, err)

	errorMsg := assertDocs(mustAddKeysToDocs(docsList.Docs), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefinedFromSchema_StripExcessiveFields(t *testing.T) {
	schema := `
		type User {
			name: String
		}`

	docs, err := GeneratePredefinedFromSDL(schema, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{"name": "John", "age": 30},
			{"name": "Fred", "age": 25},
		},
	})
	assert.NoError(t, err)

	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John"},
		{"name": "Fred"},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefinedFromSchema_OneToOne(t *testing.T) {
	schema := `
		type User {
			name: String
			device: Device
		}
		type Device {
			model: String
			owner: User
		}`

	docs, err := GeneratePredefinedFromSDL(schema, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{
				"name": "John",
				"device": map[string]any{
					"model": "iPhone",
				},
			},
			{
				"name": "Fred",
				"device": map[string]any{
					"model": "MacBook",
				},
			},
		},
	})
	assert.NoError(t, err)

	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John"},
		{"name": "Fred"},
		{"model": "iPhone", "owner_id": mustGetDocKeyFromDocMap(map[string]any{"name": "John"})},
		{"model": "MacBook", "owner_id": mustGetDocKeyFromDocMap(map[string]any{"name": "Fred"})},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefinedFromSchema_OneToOnePrimary(t *testing.T) {
	schema := `
		type User {
			name: String
			device: Device @primary
		}
		type Device {
			model: String
			owner: User
		}`

	docs, err := GeneratePredefinedFromSDL(schema, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{
				"name": "John",
				"device": map[string]any{
					"model": "iPhone",
				},
			},
			{
				"name": "Fred",
				"device": map[string]any{
					"model": "MacBook",
				},
			},
		},
	})
	assert.NoError(t, err)

	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John", "device_id": mustGetDocKeyFromDocMap(map[string]any{"model": "iPhone"})},
		{"name": "Fred", "device_id": mustGetDocKeyFromDocMap(map[string]any{"model": "MacBook"})},
		{"model": "iPhone"},
		{"model": "MacBook"},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefinedFromSchema_OneToMany(t *testing.T) {
	schema := `
		type User {
			name: String
			devices: [Device]
		}
		type Device {
			model: String
			owner: User
		}`

	docs, err := GeneratePredefinedFromSDL(schema, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{
				"name": "John",
				"devices": []map[string]any{
					{"model": "iPhone"},
					{"model": "PlayStation"},
				},
			},
			{
				"name": "Fred",
				"devices": []map[string]any{
					{"model": "Surface"},
					{"model": "Pixel"},
				},
			},
		},
	})
	assert.NoError(t, err)

	johnDocKey := mustGetDocKeyFromDocMap(map[string]any{"name": "John"})
	fredDocKey := mustGetDocKeyFromDocMap(map[string]any{"name": "Fred"})
	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John"},
		{"name": "Fred"},
		{"model": "iPhone", "owner_id": johnDocKey},
		{"model": "PlayStation", "owner_id": johnDocKey},
		{"model": "Surface", "owner_id": fredDocKey},
		{"model": "Pixel", "owner_id": fredDocKey},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefinedFromSchema_OneToManyToOne(t *testing.T) {
	schema := `
		type User {
			name: String
			devices: [Device]
		}
		type Device {
			model: String
			owner: User
			specs: Specs
		}
		type Specs {
			CPU: String
			device: Device @primary
		}`

	docs, err := GeneratePredefinedFromSDL(schema, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{
				"name": "John",
				"devices": []map[string]any{
					{
						"model": "iPhone",
						"specs": map[string]any{
							"CPU": "A13",
						},
					},
					{
						"model": "MacBook",
						"specs": map[string]any{
							"CPU": "M2",
						},
					},
				},
			},
		},
	})
	assert.NoError(t, err)

	johnDocKey := mustGetDocKeyFromDocMap(map[string]any{"name": "John"})
	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John"},
		{"model": "iPhone", "owner_id": johnDocKey},
		{"model": "MacBook", "owner_id": johnDocKey},
		{"CPU": "A13", "device_id": mustGetDocKeyFromDocMap(map[string]any{"model": "iPhone", "owner_id": johnDocKey})},
		{"CPU": "M2", "device_id": mustGetDocKeyFromDocMap(map[string]any{"model": "MacBook", "owner_id": johnDocKey})},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}

func TestGeneratePredefined_OneToMany(t *testing.T) {
	defs := []client.CollectionDefinition{
		{
			Description: client.CollectionDescription{
				Name: "User",
				ID:   0,
			},
			Schema: client.SchemaDescription{
				Name: "User",
				Fields: []client.FieldDescription{
					{
						Name: "name",
						Kind: client.FieldKind_STRING,
					},
					{
						Name:         "devices",
						Kind:         client.FieldKind_FOREIGN_OBJECT_ARRAY,
						Schema:       "Device",
						RelationType: client.Relation_Type_MANY | client.Relation_Type_ONEMANY,
					},
				},
			},
		},
		{
			Description: client.CollectionDescription{
				Name: "Device",
				ID:   1,
			},
			Schema: client.SchemaDescription{
				Name: "Device",
				Fields: []client.FieldDescription{
					{
						Name: "model",
						Kind: client.FieldKind_STRING,
					},
					{
						Name:   "owner",
						Kind:   client.FieldKind_FOREIGN_OBJECT,
						Schema: "User",
						RelationType: client.Relation_Type_ONE |
							client.Relation_Type_ONEMANY |
							client.Relation_Type_Primary,
					},
				},
			},
		},
	}
	docs, err := GeneratePredefined(defs, DocsList{
		ColName: "User",
		Docs: []map[string]any{
			{
				"name": "John",
				"devices": []map[string]any{
					{"model": "iPhone"},
					{"model": "PlayStation"},
				},
			},
			{
				"name": "Fred",
				"devices": []map[string]any{
					{"model": "Surface"},
					{"model": "Pixel"},
				},
			},
		},
	})
	assert.NoError(t, err)

	johnDocKey := mustGetDocKeyFromDocMap(map[string]any{"name": "John"})
	fredDocKey := mustGetDocKeyFromDocMap(map[string]any{"name": "Fred"})
	errorMsg := assertDocs(mustAddKeysToDocs([]map[string]any{
		{"name": "John"},
		{"name": "Fred"},
		{"model": "iPhone", "owner_id": johnDocKey},
		{"model": "PlayStation", "owner_id": johnDocKey},
		{"model": "Surface", "owner_id": fredDocKey},
		{"model": "Pixel", "owner_id": fredDocKey},
	}), docs)
	if errorMsg != "" {
		t.Error(errorMsg)
	}
}
