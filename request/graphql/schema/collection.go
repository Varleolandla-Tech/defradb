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
	"context"
	"fmt"
	"sort"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"

	"github.com/graphql-go/graphql/language/ast"
	gqlp "github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
)

// FromString parses a GQL SDL string into a set of collection descriptions.
func FromString(ctx context.Context, schemaString string) ([]client.CollectionDescription, error) {
	source := source.NewSource(&source.Source{
		Body: []byte(schemaString),
	})

	doc, err := gqlp.Parse(
		gqlp.ParseParams{
			Source: source,
		},
	)
	if err != nil {
		return nil, err
	}

	desc, err := FromAst(ctx, doc)
	return desc, err
}

func FromAst(ctx context.Context, doc *ast.Document) ([]client.CollectionDescription, error) {
	relationManager := NewRelationManager()
	descriptions := []client.CollectionDescription{}

	for _, def := range doc.Definitions {
		switch defType := def.(type) {
		case *ast.ObjectDefinition:
			description, err := FromAstDefinition(ctx, relationManager, defType)
			if err != nil {
				return nil, err
			}

			descriptions = append(descriptions, description)

		default:
			// Do nothing, ignore it and continue
			continue
		}
	}

	// The details on the relations between objects depend on both sides
	// of the relationship.  The relation manager handles this, and must be applied
	// after all the collections have been processed.
	err := finalizeRelations(relationManager, descriptions)
	if err != nil {
		return nil, err
	}

	return descriptions, nil
}

func FromAstDefinition(
	ctx context.Context,
	relationManager *RelationManager,
	def *ast.ObjectDefinition,
) (client.CollectionDescription, error) {
	fieldDescriptions := []client.FieldDescription{
		{
			Name: request.DocKeyFieldName,
			Kind: client.FieldKind_DocKey,
			Typ:  client.NONE_CRDT,
		},
	}

	for _, field := range def.Fields {
		kind, err := astTypeToKind(field.Type)
		if err != nil {
			return client.CollectionDescription{}, err
		}

		schema := ""
		relationName := ""
		relationType := client.RelationType(0)

		if kind == client.FieldKind_FOREIGN_OBJECT || kind == client.FieldKind_FOREIGN_OBJECT_ARRAY {
			if kind == client.FieldKind_FOREIGN_OBJECT {
				schema = field.Type.(*ast.Named).Name.Value
				relationType = client.Relation_Type_ONE
				if _, exists := findDirective(field, "primary"); exists {
					relationType |= client.Relation_Type_Primary
				}

				// An _id field is added for every 1-N relationship from this object.
				fieldDescriptions = append(fieldDescriptions, client.FieldDescription{
					Name:         fmt.Sprintf("%s_id", field.Name.Value),
					Kind:         client.FieldKind_DocKey,
					Typ:          defaultCRDTForFieldKind[client.FieldKind_DocKey],
					RelationType: client.Relation_Type_INTERNAL_ID,
				})
			} else if kind == client.FieldKind_FOREIGN_OBJECT_ARRAY {
				schema = field.Type.(*ast.List).Type.(*ast.Named).Name.Value
				relationType = client.Relation_Type_MANY
			}

			relationName, err = getRelationshipName(field, def.Name.Value, schema)
			if err != nil {
				return client.CollectionDescription{}, err
			}

			// Register the relationship so that the relationship manager can evaluate
			// relationsip properties dependent on both collections in the relationship.
			_, err := relationManager.RegisterSingle(
				relationName,
				schema,
				field.Name.Value,
				relationType,
			)
			if err != nil {
				return client.CollectionDescription{}, err
			}
		}

		fieldDescription := client.FieldDescription{
			Name:         field.Name.Value,
			Kind:         kind,
			Typ:          defaultCRDTForFieldKind[kind],
			Schema:       schema,
			RelationName: relationName,
			RelationType: relationType,
		}

		fieldDescriptions = append(fieldDescriptions, fieldDescription)
	}

	// sort the fields lexicographically
	sort.Slice(fieldDescriptions, func(i, j int) bool {
		// make sure that the _key (DocKeyFieldName) is always at the beginning
		if fieldDescriptions[i].Name == request.DocKeyFieldName {
			return true
		} else if fieldDescriptions[j].Name == request.DocKeyFieldName {
			return false
		}
		return fieldDescriptions[i].Name < fieldDescriptions[j].Name
	})

	return client.CollectionDescription{
		Name: def.Name.Value,
		Schema: client.SchemaDescription{
			Name:   def.Name.Value,
			Fields: fieldDescriptions,
		},
	}, nil
}

func astTypeToKind(t ast.Type) (client.FieldKind, error) {
	const (
		typeID       string = "ID"
		typeBoolean  string = "Boolean"
		typeInt      string = "Int"
		typeFloat    string = "Float"
		typeDateTime string = "DateTime"
		typeString   string = "String"
	)

	switch astTypeVal := t.(type) {
	case *ast.List:
		switch innerAstTypeVal := astTypeVal.Type.(type) {
		case *ast.NonNull:
			switch innerAstTypeVal.Type.(*ast.Named).Name.Value {
			case typeBoolean:
				return client.FieldKind_BOOL_ARRAY, nil
			case typeInt:
				return client.FieldKind_INT_ARRAY, nil
			case typeFloat:
				return client.FieldKind_FLOAT_ARRAY, nil
			case typeString:
				return client.FieldKind_STRING_ARRAY, nil
			default:
				return 0, NewErrTypeNotFound(innerAstTypeVal.Type.(*ast.Named).Name.Value)
			}

		default:
			switch astTypeVal.Type.(*ast.Named).Name.Value {
			case typeBoolean:
				return client.FieldKind_NILLABLE_BOOL_ARRAY, nil
			case typeInt:
				return client.FieldKind_NILLABLE_INT_ARRAY, nil
			case typeFloat:
				return client.FieldKind_NILLABLE_FLOAT_ARRAY, nil
			case typeString:
				return client.FieldKind_NILLABLE_STRING_ARRAY, nil
			default:
				return client.FieldKind_FOREIGN_OBJECT_ARRAY, nil
			}
		}

	case *ast.Named:
		switch astTypeVal.Name.Value {
		case typeID:
			return client.FieldKind_DocKey, nil
		case typeBoolean:
			return client.FieldKind_BOOL, nil
		case typeInt:
			return client.FieldKind_INT, nil
		case typeFloat:
			return client.FieldKind_FLOAT, nil
		case typeDateTime:
			return client.FieldKind_DATETIME, nil
		case typeString:
			return client.FieldKind_STRING, nil
		default:
			return client.FieldKind_FOREIGN_OBJECT, nil
		}

	default:
		return 0, NewErrTypeNotFound(t.String())
	}
}

func finalizeRelations(relationManager *RelationManager, descriptions []client.CollectionDescription) error {
	for _, description := range descriptions {
		for i, field := range description.Schema.Fields {
			if field.RelationType == 0 || field.RelationType&client.Relation_Type_INTERNAL_ID != 0 {
				continue
			}

			rel, err := relationManager.GetRelation(field.RelationName)
			if err != nil {
				return err
			}

			_, fieldRelationType, ok := rel.GetField(field.Schema, field.Name)
			if !ok {
				return NewErrRelationMissingField(field.Schema, field.Name)
			}

			field.RelationType = rel.Kind() | fieldRelationType
			description.Schema.Fields[i] = field
		}
	}

	return nil
}
