// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package core

import (
	"context"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/sourcenetwork/immutable"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"
	"github.com/sourcenetwork/defradb/datastore"
)

// SchemaDefinition represents a schema definition.
type SchemaDefinition struct {
	// The name of this schema definition.
	Name string

	// The serialized definition of this schema definition.
	// todo: this needs to be properly typed and handled according to
	// https://github.com/sourcenetwork/defradb/issues/863
	Body []byte
}

// Parser represents the object responsible for handling stuff specific to a query language.
// This includes schema and request parsing, and introspection.
type Parser interface {
	// BuildRequestAST builds and return AST for the given request.
	BuildRequestAST(request string) (*ast.Document, error)

	// Returns true if the given request ast is an introspection request.
	IsIntrospection(*ast.Document) bool

	// Executes the given introspection request.
	ExecuteIntrospection(request string) *client.RequestResult

	// Parses the given request, returning a strongly typed model of that request.
	Parse(*ast.Document) (*request.Request, []error)

	// NewFilterFromString creates a new filter from a string.
	NewFilterFromString(collectionType string, body string) (immutable.Option[request.Filter], error)

	// ParseSDL parses an SDL string into a set of collection descriptions.
	ParseSDL(ctx context.Context, schemaString string) ([]client.CollectionDescription, error)

	// Adds the given schema to this parser's model.
	SetSchema(ctx context.Context, txn datastore.Txn, collections []client.CollectionDescription) error
}
