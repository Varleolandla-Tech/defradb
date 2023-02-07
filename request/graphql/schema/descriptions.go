// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package schema

import (
	gql "github.com/graphql-go/graphql"

	"github.com/sourcenetwork/defradb/client"
)

var (
	// this is only here as a reference, and not to be used
	// directly. As it will yield incorrect and unexpected
	// results

	//nolint:unused
	gqlTypeToFieldKindReference = map[gql.Type]client.FieldKind{
		gql.ID:        client.FieldKind_DocKey,
		gql.Boolean:   client.FieldKind_BOOL,
		gql.Int:       client.FieldKind_INT,
		gql.Float:     client.FieldKind_FLOAT,
		gql.DateTime:  client.FieldKind_DATETIME,
		gql.String:    client.FieldKind_STRING,
		&gql.Object{}: client.FieldKind_FOREIGN_OBJECT,
		&gql.List{}:   client.FieldKind_FOREIGN_OBJECT_ARRAY,
		// More custom ones to come
		// - JSON
		// - ByteArray
		// - Counters
	}

	fieldKindToGQLType = map[client.FieldKind]gql.Type{
		client.FieldKind_DocKey:                gql.ID,
		client.FieldKind_BOOL:                  gql.Boolean,
		client.FieldKind_BOOL_ARRAY:            gql.NewList(gql.NewNonNull(gql.Boolean)),
		client.FieldKind_NILLABLE_BOOL_ARRAY:   gql.NewList(gql.Boolean),
		client.FieldKind_INT:                   gql.Int,
		client.FieldKind_INT_ARRAY:             gql.NewList(gql.NewNonNull(gql.Int)),
		client.FieldKind_NILLABLE_INT_ARRAY:    gql.NewList(gql.Int),
		client.FieldKind_FLOAT:                 gql.Float,
		client.FieldKind_FLOAT_ARRAY:           gql.NewList(gql.NewNonNull(gql.Float)),
		client.FieldKind_NILLABLE_FLOAT_ARRAY:  gql.NewList(gql.Float),
		client.FieldKind_DATETIME:              gql.DateTime,
		client.FieldKind_STRING:                gql.String,
		client.FieldKind_STRING_ARRAY:          gql.NewList(gql.NewNonNull(gql.String)),
		client.FieldKind_NILLABLE_STRING_ARRAY: gql.NewList(gql.String),
	}

	// This map is fine to use
	defaultCRDTForFieldKind = map[client.FieldKind]client.CType{
		client.FieldKind_DocKey:                client.LWW_REGISTER,
		client.FieldKind_BOOL:                  client.LWW_REGISTER,
		client.FieldKind_BOOL_ARRAY:            client.LWW_REGISTER,
		client.FieldKind_NILLABLE_BOOL_ARRAY:   client.LWW_REGISTER,
		client.FieldKind_INT:                   client.LWW_REGISTER,
		client.FieldKind_INT_ARRAY:             client.LWW_REGISTER,
		client.FieldKind_NILLABLE_INT_ARRAY:    client.LWW_REGISTER,
		client.FieldKind_FLOAT:                 client.LWW_REGISTER,
		client.FieldKind_FLOAT_ARRAY:           client.LWW_REGISTER,
		client.FieldKind_NILLABLE_FLOAT_ARRAY:  client.LWW_REGISTER,
		client.FieldKind_DATETIME:              client.LWW_REGISTER,
		client.FieldKind_STRING:                client.LWW_REGISTER,
		client.FieldKind_STRING_ARRAY:          client.LWW_REGISTER,
		client.FieldKind_NILLABLE_STRING_ARRAY: client.LWW_REGISTER,
		client.FieldKind_FOREIGN_OBJECT:        client.NONE_CRDT,
		client.FieldKind_FOREIGN_OBJECT_ARRAY:  client.NONE_CRDT,
	}
)

/*

type book {
	name: String
	rating: Float
	author: author @primary
}

// don't need to worry about IDs and FieldIDs

return client.CollectionDescription{
		Name: "book",
		ID:   uint32(2),
		Schema: client.SchemaDescription{
			ID:       uint32(2),
			FieldIDs: []uint32{1, 2, 3, 4, 5},
			Fields: []client.FieldDescription{
				client.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				client.FieldDescription{
					Name: "name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  client.LWW_REGISTER,
				},
				client.FieldDescription{
					Name: "rating",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_FLOAT,
					Typ:  client.LWW_REGISTER,
				},
				client.FieldDescription{
					Name:   "author",
					ID:     base.FieldID(5),
					Kind:   base.FieldKind_FOREIGN_OBJECT,
					Schema: "author",
					Typ:    client.NONE_CRDT,
					Meta:   base.Relation_Type_ONE | base.Relation_Type_Primary,
				},
				client.FieldDescription{
					Name: "author_id",
					ID:   base.FieldID(6),
					Kind: base.FieldKind_DocKey,
					Typ:  client.LWW_REGISTER,
				},
			},
		},
		Indexes: []client.IndexDescription{
			client.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}

	return client.CollectionDescription{
		Name: "author",
		ID:   uint32(3),
		Schema: client.SchemaDescription{
			ID:       uint32(3),
			Name:     "author",
			FieldIDs: []uint32{1, 2, 3, 4, 5},
			Fields: []client.FieldDescription{
				client.FieldDescription{
					Name: "_key",
					ID:   base.FieldID(1),
					Kind: base.FieldKind_DocKey,
				},
				client.FieldDescription{
					Name: "name",
					ID:   base.FieldID(2),
					Kind: base.FieldKind_STRING,
					Typ:  client.LWW_REGISTER,
				},
				client.FieldDescription{
					Name: "age",
					ID:   base.FieldID(3),
					Kind: base.FieldKind_INT,
					Typ:  client.LWW_REGISTER,
				},
				client.FieldDescription{
					Name: "verified",
					ID:   base.FieldID(4),
					Kind: base.FieldKind_BOOL,
					Typ:  client.LWW_REGISTER,
				},
				client.FieldDescription{
					Name:   "published",
					ID:     base.FieldID(5),
					Kind:   base.FieldKind_FOREIGN_OBJECT_ARRAY,
					Schema: "book",
					Typ:    client.NONE_CRDT,
					Meta:   base.Relation_Type_ONEMANY,
				},
			},
		},
		Indexes: []client.IndexDescription{
			client.IndexDescription{
				Name:    "primary",
				ID:      uint32(0),
				Primary: true,
				Unique:  true,
			},
		},
	}
*/
