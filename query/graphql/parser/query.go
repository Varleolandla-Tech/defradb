// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package parser

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/graphql-go/graphql/language/ast"
)

type SelectionType int

const (
	NoneSelection = iota
	ObjectSelection
	CommitSelection

	VersionFieldName = "_version"
	GroupFieldName   = "_group"
	DocKeyFieldName  = "_key"
	CountFieldName   = "_count"
	SumFieldName     = "_sum"
	AverageFieldName = "_avg"
	HiddenFieldName  = "_hidden"
)

// Enum for different types of read Select queries
type SelectQueryType int

const (
	ScanQuery = iota
	VersionedScanQuery
)

var dbAPIQueryNames = map[string]bool{
	"latestCommits": true,
	"allCommits":    true,
	"commit":        true,
}

var ReservedFields = map[string]bool{
	VersionFieldName: true,
	GroupFieldName:   true,
	CountFieldName:   true,
	SumFieldName:     true,
	AverageFieldName: true,
	HiddenFieldName:  true,
	DocKeyFieldName:  true,
}

var Aggregates = map[string]struct{}{
	CountFieldName:   {},
	SumFieldName:     {},
	AverageFieldName: {},
}

type Query struct {
	Queries   []*OperationDefinition
	Mutations []*OperationDefinition
	Statement *ast.Document
}

func (q Query) GetStatement() ast.Node {
	return q.Statement
}

type OperationDefinition struct {
	Name       string
	Selections []Selection

	Statement *ast.OperationDefinition
}

func (q OperationDefinition) GetStatement() ast.Node {
	return q.Statement
}

// type SelectionSet struct {
// 	Selections []Selection
// }

type Selection interface {
	Statement
	GetName() string
	GetAlias() string
	GetSelections() []Selection
	GetRoot() SelectionType
}

// Select is a complex Field with strong typing
// It used for sub types in a query. Includes
// fields, and query arguments like filters,
// limits, etc.
type Select struct {
	// The unique, internal name of the Select - this may differ from that which
	// is visible in the query string
	Name string
	// The identifier to be used in the rendered results, typically specified by
	// the user.
	Alias string
	// The name by which the the consumer refers to the select, e.g. `_group`
	ExternalName   string
	CollectionName string
	// If true, this Select will not be exposed/rendered to the consumer and will
	// only be used internally
	Hidden bool

	// QueryType indicates what kind of query this is
	// Currently supports: ScanQuery, VersionedScanQuery
	QueryType SelectQueryType

	// Root is the top level query parsed type
	Root SelectionType

	DocKeys []string
	CID     string

	Filter  *Filter
	Limit   *Limit
	OrderBy *OrderBy
	GroupBy *GroupBy

	Fields []Selection

	// raw graphql statement
	Statement *ast.Field
}

func (s Select) GetRoot() SelectionType {
	return s.Root
}

func (s Select) GetStatement() ast.Node {
	return s.Statement
}

func (s Select) GetSelections() []Selection {
	return s.Fields
}

func (s Select) GetName() string {
	return s.Name
}

func (s Select) GetAlias() string {
	return s.Alias
}

// Equal compares the given Selects and returns true if they can be considered equal.
// Note: Currently only compares Name, ExternalName and Filter as that is all that is
// currently required, but this should be extended in the future.
func (s Select) Equal(other Select) bool {
	if s.Name != other.Name &&
		s.ExternalName != other.ExternalName {
		return false
	}

	if s.Filter == nil {
		return other.Filter == nil
	}

	return reflect.DeepEqual(s.Filter.Conditions, other.Filter.Conditions)
}

// Clone shallow-clones the Select using the provided names.
// Note: Currently only Filter and Statement are taken from the source select,
// this will likely expand in the near future.
func (s Select) Clone(name string, externalName string) *Select {
	return &Select{
		Name:         name,
		ExternalName: externalName,
		Filter:       s.Filter,
		Statement:    s.Statement,
	}
}

// Field implements Selection
type Field struct {
	Name  string
	Alias string

	Root SelectionType

	// raw graphql statement
	Statement *ast.Field
}

func (c Field) GetRoot() SelectionType {
	return c.Root
}

// GetSelectionSet implements Selection
func (f Field) GetSelections() []Selection {
	return []Selection{}
}

func (f Field) GetName() string {
	return f.Name
}

func (f Field) GetAlias() string {
	return f.Alias
}

func (f Field) GetStatement() ast.Node {
	return f.Statement
}

type GroupBy struct {
	Fields []string
}

type SortDirection string

const (
	ASC  SortDirection = "ASC"
	DESC SortDirection = "DESC"
)

var (
	NameToSortDirection = map[string]SortDirection{
		"ASC":  ASC,
		"DESC": DESC,
	}
)

type SortCondition struct {
	// field may be a compound field statement
	// since the sort statement allows sorting on
	// sub objects.
	//
	// Given the statement: {sort: {author: {birthday: DESC}}}
	// The field value would be "author.birthday"
	// and the direction would be "DESC"
	Field     string
	Direction SortDirection
}
type OrderBy struct {
	Conditions []SortCondition
	Statement  *ast.ObjectValue
}

type Limit struct {
	Limit  int64
	Offset int64
}

// type SubQuery struct{}

// type

// ParseQuery parses a root ast.Document, and returns a
// formatted Query object.
// Requires a non-nil doc, will error if given a nil
// doc
func ParseQuery(doc *ast.Document) (*Query, error) {
	if doc == nil {
		return nil, errors.New("ParseQuery requires a non nil ast.Document")
	}
	q := &Query{
		Statement: doc,
		Queries:   make([]*OperationDefinition, 0),
		Mutations: make([]*OperationDefinition, 0),
	}
	for _, def := range q.Statement.Definitions {
		switch node := def.(type) {
		case *ast.OperationDefinition:
			if node.Operation == "query" {
				// parse query or mutation operation definition
				qdef, err := parseQueryOperationDefinition(node)
				if err != nil {
					return nil, err
				}
				q.Queries = append(q.Queries, qdef)
			} else if node.Operation == "mutation" {
				mdef, err := parseMutationOperationDefinition(node)
				if err != nil {
					return nil, err
				}
				q.Mutations = append(q.Mutations, mdef)
			} else {
				return nil, errors.New("Unkown graphql operation type")
			}
		}
	}

	return q, nil
}

// parseOperationDefinition parses the individual GraphQL
// 'query' operations, which there may be multiple of.
func parseQueryOperationDefinition(def *ast.OperationDefinition) (*OperationDefinition, error) {
	qdef := &OperationDefinition{
		Statement:  def,
		Selections: make([]Selection, len(def.SelectionSet.Selections)),
	}
	if def.Name != nil {
		qdef.Name = def.Name.Value
	}
	for i, selection := range qdef.Statement.SelectionSet.Selections {
		var parsed Selection
		var err error
		switch node := selection.(type) {
		case *ast.Field:
			// which query type is this
			// database API query
			// object query
			// etc
			_, exists := dbAPIQueryNames[node.Name.Value]
			if exists {
				// the query matches a reserved DB API query name
				parsed, err = parseAPIQuery(node)
			} else {
				// the query doesn't match a reserve name
				// so its probably a generated query
				parsed, err = parseSelect(ObjectSelection, node, i)
			}
			if err != nil {
				return nil, err
			}

			qdef.Selections[i] = parsed
		}
	}
	return qdef, nil
}

// @todo: Create separate select parse functions
// for generated object queries, and general
// API queries

// parseSelect parses a typed selection field
// which includes sub fields, and may include
// filters, limits, orders, etc..
func parseSelect(rootType SelectionType, field *ast.Field, index int) (*Select, error) {
	name, alias := getFieldName(field, index)

	slct := &Select{
		Name:         name,
		Alias:        alias,
		ExternalName: field.Name.Value,
		Root:         rootType,
		Statement:    field,
	}

	// parse arguments
	for _, argument := range field.Arguments {
		prop, astValue := getArgumentKeyValue(field, argument)

		// parse filter
		if prop == "filter" {
			obj := astValue.(*ast.ObjectValue)
			filter, err := NewFilter(obj)
			if err != nil {
				return slct, err
			}

			slct.Filter = filter
		} else if prop == "dockey" { // parse single dockey query field
			val := astValue.(*ast.StringValue)
			slct.DocKeys = []string{val.Value}
		} else if prop == "dockeys" {
			docKeyValues := astValue.(*ast.ListValue).Values
			docKeys := make([]string, len(docKeyValues))
			for i, value := range docKeyValues {
				docKeys[i] = value.(*ast.StringValue).Value
			}
			slct.DocKeys = docKeys
		} else if prop == "cid" { // parse single CID query field
			val := astValue.(*ast.StringValue)
			slct.CID = val.Value
		} else if prop == "limit" { // parse limit/offset
			val := astValue.(*ast.IntValue)
			i, err := strconv.ParseInt(val.Value, 10, 64)
			if err != nil {
				return slct, err
			}
			if slct.Limit == nil {
				slct.Limit = &Limit{}
			}
			slct.Limit.Limit = i
		} else if prop == "offset" { // parse limit/offset
			val := astValue.(*ast.IntValue)
			i, err := strconv.ParseInt(val.Value, 10, 64)
			if err != nil {
				return slct, err
			}
			if slct.Limit == nil {
				slct.Limit = &Limit{}
			}
			slct.Limit.Offset = i
		} else if prop == "order" { // parse sort (order by)
			obj := astValue.(*ast.ObjectValue)
			cond, err := ParseConditionsInOrder(obj)
			if err != nil {
				return nil, err
			}
			slct.OrderBy = &OrderBy{
				Conditions: cond,
				Statement:  obj,
			}
		} else if prop == "groupBy" {
			obj := astValue.(*ast.ListValue)
			fields := make([]string, 0)
			for _, v := range obj.Values {
				fields = append(fields, v.GetValue().(string))
			}

			slct.GroupBy = &GroupBy{
				Fields: fields,
			}
		}

		if len(slct.DocKeys) != 0 && len(slct.CID) != 0 {
			slct.QueryType = VersionedScanQuery
		} else {
			slct.QueryType = ScanQuery
		}
	}

	// if theres no field selections, just return
	if field.SelectionSet == nil {
		return slct, nil
	}

	// parse field selections
	var err error
	slct.Fields, err = parseSelectFields(slct.Root, field.SelectionSet)
	if err != nil {
		return nil, err
	}

	return slct, err
}

// getArgumentKeyValue returns the relevant arguement name and value for the given field-argument
// Note: this function will likely need some rework when adding more aggregate options (e.g. limit)
func getArgumentKeyValue(field *ast.Field, argument *ast.Argument) (string, ast.Value) {
	if _, isAggregate := Aggregates[field.Name.Value]; isAggregate {
		switch innerProps := argument.Value.(type) {
		case *ast.ObjectValue:
			for _, innerV := range innerProps.Fields {
				if innerV.Name.Value == "filter" {
					return "filter", innerV.Value
				}
			}
		}
	}
	return argument.Name.Value, argument.Value
}

// getFieldName returns the internal name and alias of the given field at the given index.
// The returned name/alias may be different from the values directly on the field in order to
// distinguish between multiple aliases of the same underlying field.
func getFieldName(field *ast.Field, index int) (name string, alias string) {
	// Fields that take arguments (e.g. filters) that can be aliased must be renamed internally
	// to allow code to distinguish between multiple properties targeting the same underlying field
	// that may or may not have different arguments.  It is hoped that this renaming can be removed
	// once we migrate to an array-based document structure as per
	// https://github.com/sourcenetwork/defradb/issues/395
	if _, isAggregate := Aggregates[field.Name.Value]; isAggregate || field.Name.Value == GroupFieldName {
		name = fmt.Sprintf("_agg%v", index)
		if field.Alias == nil {
			alias = field.Name.Value
		} else {
			alias = field.Alias.Value
		}
	} else {
		name = field.Name.Value
		if field.Alias != nil {
			alias = field.Alias.Value
		}
	}

	return name, alias
}

func parseSelectFields(root SelectionType, fields *ast.SelectionSet) ([]Selection, error) {
	selections := make([]Selection, len(fields.Selections))
	// parse field selections
	for i, selection := range fields.Selections {
		switch node := selection.(type) {
		case *ast.Field:
			if _, isAggregate := Aggregates[node.Name.Value]; isAggregate {
				s, err := parseSelect(root, node, i)
				if err != nil {
					return nil, err
				}
				selections[i] = s
			} else if node.SelectionSet == nil { // regular field
				f, err := parseField(root, node)
				if err != nil {
					return nil, err
				}
				selections[i] = f
			} else { // sub type with extra fields
				subroot := root
				switch node.Name.Value {
				case "_version":
					subroot = CommitSelection
				}
				s, err := parseSelect(subroot, node, i)
				if err != nil {
					return nil, err
				}
				selections[i] = s
			}
		}
	}

	return selections, nil
}

// parseField simply parses the Name/Alias
// into a Field type
func parseField(root SelectionType, field *ast.Field) (*Field, error) {
	var alias string

	name := field.Name.Value
	if field.Alias != nil {
		alias = field.Alias.Value
	}

	f := &Field{
		Root:      root,
		Name:      name,
		Statement: field,
		Alias:     alias,
	}
	return f, nil
}

func parseAPIQuery(field *ast.Field) (Selection, error) {
	switch field.Name.Value {
	case "latestCommits", "allCommits", "commit":
		return parseCommitSelect(field)
	default:
		return nil, errors.New("Unknown query")
	}
}

// The relative target/path from the object hosting an aggregate, to the property to
// be aggregated.
type AggregateTarget struct {
	// The property on the object hosting the aggregate.  This should never be empty
	HostProperty string
	// The static name of the target host property as it appears in the aggregate
	// query.  For example `_group`.
	ExternalHostName string
	// The property on the `HostProperty` that this aggregate targets.
	//
	// This may be empty if the aggregate targets a whole collection (e.g. Count),
	// or if `HostProperty` is an inline array.
	ChildProperty string
}

// Returns the source of the aggregate as requested by the consumer
func (field Select) GetAggregateSource(host Selection) (AggregateTarget, error) {
	if len(field.Statement.Arguments) == 0 {
		return AggregateTarget{}, fmt.Errorf(
			"Aggregate must be provided with a property to aggregate.",
		)
	}

	var hostProperty string
	var externalHostName string
	var childProperty string
	switch argumentValue := field.Statement.Arguments[0].Value.GetValue().(type) {
	case string:
		externalHostName = argumentValue
	case []*ast.ObjectField:
		externalHostName = field.Statement.Arguments[0].Name.Value
		fieldArg, hasFieldArg := tryGet(argumentValue, "field")
		if hasFieldArg {
			if innerPathStringValue, isString := fieldArg.Value.GetValue().(string); isString {
				childProperty = innerPathStringValue
			}
		}
	}

	childFields := host.GetSelections()
	targetField := field.Clone(externalHostName, externalHostName)

	// Check for any fields matching the targetField
	for _, childField := range childFields {
		childSelect, isSelect := childField.(*Select)
		if isSelect && childSelect.Equal(*targetField) {
			hostProperty = childSelect.Name
			break
		}
	}

	// If we didn't find a field matching the target, we look for something with no filter,
	// as it should yield all the items required by the aggregate.
	if hostProperty == "" {
		for _, childField := range childFields {
			if childSelect, isSelect := childField.(*Select); isSelect {
				if childSelect.ExternalName == externalHostName && childSelect.Filter == nil {
					hostProperty = childSelect.Name
					break
				}
			}
		}
	}

	if hostProperty == "" {
		// child relationships use this currently due to bug https://github.com/sourcenetwork/defradb/issues/390
		hostProperty = externalHostName
	}

	return AggregateTarget{
		HostProperty:     hostProperty,
		ExternalHostName: externalHostName,
		ChildProperty:    childProperty,
	}, nil
}

func tryGet(fields []*ast.ObjectField, name string) (arg *ast.ObjectField, hasArg bool) {
	for _, field := range fields {
		if field.Name.Value == name {
			return field, true
		}
	}
	return nil, false
}
