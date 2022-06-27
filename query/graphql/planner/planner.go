// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package planner

import (
	"context"
	"fmt"
	"reflect"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/logging"
	"github.com/sourcenetwork/defradb/query/graphql/mapper"
	"github.com/sourcenetwork/defradb/query/graphql/parser"

	parserTypes "github.com/sourcenetwork/defradb/query/graphql/parser/types"
)

var (
	log = logging.MustNewLogger("defra.query.planner")
)

// planNode is an interface all nodes in the plan tree need to implement.
type planNode interface {
	// Initializes or Re-Initializes an existing planNode, often called internally by Start().
	Init() error

	// Starts any internal logic or processes required by the planNode. Should be called *after* Init().
	Start() error

	// Spans sets the planNodes target spans. This is primarily only used for a scanNode,
	// but based on the tree structure, may need to be propagated Eg. From a selectNode -> scanNode.
	Spans(core.Spans)

	// Next processes the next result doc from the query. Can only be called *after* Start().
	// Can't be called again if any previous call returns false.
	Next() (bool, error)

	// Values returns the value of the current doc, should only be called *after* Next().
	Value() core.Doc

	// Source returns the child planNode that generates the source values for this plan.
	// If a plan has no source, nil is returned.
	Source() planNode

	// Kind tells the name of concrete planNode type.
	Kind() string

	DocumentMap() *core.DocumentMapping

	// Close terminates the planNode execution and releases its resources. After this
	// method is called you can only safely call Kind() and Source() methods.
	Close() error
}

type documentIterator struct {
	currentValue core.Doc
}

func (n *documentIterator) Value() core.Doc {
	return n.currentValue
}

type docMapper struct {
	documentMapping *core.DocumentMapping
}

func (d *docMapper) DocumentMap() *core.DocumentMapping {
	return d.documentMapping
}

type ExecutionContext struct {
	context.Context
}

type PlanContext struct {
	context.Context
}

// Planner combines session state and database state to
// produce a query plan, which is run by the execution context.
type Planner struct {
	txn datastore.Txn
	db  client.DB

	ctx context.Context
}

func makePlanner(ctx context.Context, db client.DB, txn datastore.Txn) *Planner {
	return &Planner{
		txn: txn,
		db:  db,
		ctx: ctx,
	}
}

func (p *Planner) newPlan(stmt interface{}) (planNode, error) {
	switch n := stmt.(type) {
	case *parser.Query:
		if len(n.Queries) > 0 {
			return p.newPlan(n.Queries[0]) // @todo, handle multiple query statements
		} else if len(n.Mutations) > 0 {
			return p.newPlan(n.Mutations[0]) // @todo: handle multiple mutation statements
		} else {
			return nil, fmt.Errorf("Query is missing query or mutation statements")
		}

	case *parser.OperationDefinition:
		if len(n.Selections) == 0 {
			return nil, fmt.Errorf("OperationDefinition is missing selections")
		}
		return p.newPlan(n.Selections[0])

	case *parser.Select:
		m, err := mapper.ToSelect(p.ctx, p.txn, n)
		if err != nil {
			return nil, err
		}
		return p.Select(m)
	case *mapper.Select:
		return p.Select(n)

	case *parser.CommitSelect:
		m, err := mapper.ToCommitSelect(p.ctx, p.txn, n)
		if err != nil {
			return nil, err
		}
		return p.CommitSelect(m)

	case *parser.Mutation:
		m, err := mapper.ToMutation(p.ctx, p.txn, n)
		if err != nil {
			return nil, err
		}
		return p.newObjectMutationPlan(m)
	}
	return nil, fmt.Errorf("Unknown statement type %T", stmt)
}

func (p *Planner) newObjectMutationPlan(stmt *mapper.Mutation) (planNode, error) {
	switch stmt.Type {
	case mapper.CreateObjects:
		return p.CreateDoc(stmt)

	case mapper.UpdateObjects:
		return p.UpdateDocs(stmt)

	case mapper.DeleteObjects:
		return p.DeleteDocs(stmt)

	default:
		return nil, fmt.Errorf("Unknown mutation action %T", stmt.Type)
	}
}

// makePlan creates a new plan from the parsed data, optimizes the plan and returns
// an initiated plan. The caller of makePlan is also responsible of calling Close()
// on the plan to free it's resources.
func (p *Planner) makePlan(stmt interface{}) (planNode, error) {
	plan, err := p.newPlan(stmt)
	if err != nil {
		return nil, err
	}

	err = p.optimizePlan(plan)
	if err != nil {
		return nil, err
	}

	err = plan.Init()
	return plan, err
}

// optimizePlan optimizes the plan using plan expansion and wiring.
func (p *Planner) optimizePlan(plan planNode) error {
	err := p.expandPlan(plan, nil)
	return err
}

// expandPlan does a full plan graph expansion and other optimizations.
func (p *Planner) expandPlan(plan planNode, parentPlan *selectTopNode) error {
	switch n := plan.(type) {
	case *selectTopNode:
		return p.expandSelectTopNodePlan(n, parentPlan)

	case *commitSelectTopNode:
		return p.expandPlan(n.plan, parentPlan)

	case *selectNode:
		return p.expandPlan(n.source, parentPlan)

	case *typeIndexJoin:
		return p.expandTypeIndexJoinPlan(n, parentPlan)

	case *groupNode:
		for _, dataSource := range n.dataSources {
			// We only care about expanding the child source here, it is assumed that the parent source
			// is expanded elsewhere/already
			err := p.expandPlan(dataSource.childSource, parentPlan)
			if err != nil {
				return err
			}
		}
		return nil
	case MultiNode:
		return p.expandMultiNode(n, parentPlan)

	case *updateNode:
		return p.expandPlan(n.results, parentPlan)

	case *createNode:
		return p.expandPlan(n.results, parentPlan)

	default:
		return nil
	}
}

func (p *Planner) expandSelectTopNodePlan(plan *selectTopNode, parentPlan *selectTopNode) error {
	if err := p.expandPlan(plan.selectnode, plan); err != nil {
		return err
	}

	// wire up source to plan
	plan.plan = plan.selectnode

	// if group
	if plan.group != nil {
		err := p.expandGroupNodePlan(plan)
		if err != nil {
			return err
		}
		plan.plan = plan.group
	}

	p.expandAggregatePlans(plan)

	// if order
	if plan.sort != nil {
		plan.sort.plan = plan.plan
		plan.plan = plan.sort
	}

	if plan.limit != nil {
		err := p.expandLimitPlan(plan, parentPlan)
		if err != nil {
			return err
		}
	}

	return nil
}

type aggregateNode interface {
	planNode
	SetPlan(plan planNode)
}

func (p *Planner) expandAggregatePlans(plan *selectTopNode) {
	// Iterate through the aggregates backwards to ensure dependencies
	// execute *before* any aggregate dependent on them.
	for i := len(plan.aggregates) - 1; i >= 0; i-- {
		aggregate := plan.aggregates[i]
		aggregate.SetPlan(plan.plan)
		plan.plan = aggregate
	}
}

func (p *Planner) expandMultiNode(plan MultiNode, parentPlan *selectTopNode) error {
	for _, child := range plan.Children() {
		if err := p.expandPlan(child, parentPlan); err != nil {
			return err
		}
	}
	return nil
}

func (p *Planner) expandTypeIndexJoinPlan(plan *typeIndexJoin, parentPlan *selectTopNode) error {
	switch node := plan.joinPlan.(type) {
	case *typeJoinOne:
		return p.expandPlan(node.subType, parentPlan)
	case *typeJoinMany:
		return p.expandPlan(node.subType, parentPlan)
	}
	return fmt.Errorf("Unknown type index join plan")
}

func (p *Planner) expandGroupNodePlan(plan *selectTopNode) error {
	// Find the first scan node in the plan, we assume that it will be for the correct collection
	scanNode := p.walkAndFindPlanType(plan.plan, &scanNode{}).(*scanNode)
	// Check for any existing pipe nodes in the plan, we should use it if there is one
	pipe, hasPipe := p.walkAndFindPlanType(plan.plan, &pipeNode{}).(*pipeNode)

	if !hasPipe {
		newPipeNode := newPipeNode(scanNode.DocumentMap())
		pipe = &newPipeNode
		pipe.source = scanNode
	}

	if len(plan.group.childSelects) == 0 {
		dataSource := plan.group.dataSources[0]
		dataSource.parentSource = plan.plan
		dataSource.pipeNode = pipe
	}

	for i, childSelect := range plan.group.childSelects {
		childSelectNode, err := p.SelectFromSource(
			childSelect,
			pipe,
			false,
			&plan.selectnode.sourceInfo,
		)
		if err != nil {
			return err
		}

		dataSource := plan.group.dataSources[i]
		dataSource.childSource = childSelectNode
		dataSource.parentSource = plan.plan
		dataSource.pipeNode = pipe
	}

	if err := p.walkAndReplacePlan(plan.group, scanNode, pipe); err != nil {
		return err
	}

	for _, dataSource := range plan.group.dataSources {
		err := p.expandPlan(dataSource.childSource, plan)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Planner) expandLimitPlan(plan *selectTopNode, parentPlan *selectTopNode) error {
	switch l := plan.limit.(type) {
	case *hardLimitNode:
		if l == nil {
			return nil
		}

		// Limits get more complicated with groups and have to be handled internally, so we ensure
		// any limit plan is disabled here
		if parentPlan != nil && parentPlan.group != nil && len(parentPlan.group.childSelects) != 0 {
			plan.limit = nil
			return nil
		}

		// if this is a child node, and the parent select has an aggregate then we need to
		// replace the hard limit with a render limit to allow the full set of child records
		// to be aggregated
		if parentPlan != nil && len(parentPlan.aggregates) > 0 {
			renderLimit, err := p.RenderLimit(
				parentPlan.documentMapping,
				&parserTypes.Limit{
					Offset: l.offset,
					Limit:  l.limit,
				},
			)
			if err != nil {
				return err
			}
			plan.limit = renderLimit

			renderLimit.plan = plan.plan
			plan.plan = plan.limit
		} else {
			l.plan = plan.plan
			plan.plan = plan.limit
		}
	case *renderLimitNode:
		if l == nil {
			return nil
		}

		l.plan = plan.plan
		plan.plan = plan.limit
	}
	return nil
}

// walkAndReplace walks through the provided plan, and searches for an instance
// of the target plan, and replaces it with the replace plan
func (p *Planner) walkAndReplacePlan(plan, target, replace planNode) error {
	src := plan.Source()
	if src == nil {
		return nil
	}

	// not our target plan
	// walk into the next plan
	if src != target {
		return p.walkAndReplacePlan(src, target, replace)
	}

	// We've found our plan, figure out what type our current plan is
	// and update accordingly
	switch node := plan.(type) {
	case *selectNode:
		node.source = replace
	case *typeJoinOne:
		node.root = replace
	case *typeJoinMany:
		node.root = replace
	case *pipeNode:
		/* Do nothing - pipe nodes should not be replaced */
	// @todo: add more nodes that apply here
	default:
		return fmt.Errorf("Unknown plan node type to replace: %T", node)
	}

	return nil
}

// walkAndFindPlanType walks through the plan graph, and returns the first
// instance of a plan, that matches the same type as the target plan
func (p *Planner) walkAndFindPlanType(plan, target planNode) planNode {
	src := plan
	if src == nil {
		return nil
	}

	srcType := reflect.TypeOf(src)
	targetType := reflect.TypeOf(target)
	if srcType != targetType {
		return p.walkAndFindPlanType(plan.Source(), target)
	}

	return src
}

// explainRequest walks through the plan graph, and outputs the concrete planNodes that should
//  be executed, maintaing their order in the plan graph (does not actually execute them).
func (p *Planner) explainRequest(
	ctx context.Context,
	plan planNode,
) ([]map[string]interface{}, error) {
	if plan == nil {
		return nil, fmt.Errorf("Can't explain request of a nil plan.")
	}

	explainGraph, err := buildExplainGraph(plan)
	if err != nil {
		return nil, err
	}

	topExplainGraph := []map[string]interface{}{
		{
			parserTypes.ExplainLabel: explainGraph,
		},
	}

	return topExplainGraph, plan.Close()
}

// executeRequest executes the plan graph that represents the request that was made.
func (p *Planner) executeRequest(
	ctx context.Context,
	plan planNode,
) ([]map[string]interface{}, error) {
	if plan == nil {
		return nil, fmt.Errorf("Can't execute request of a nil plan.")
	}

	if err := plan.Start(); err != nil {
		return nil, multiErr(err, plan.Close())
	}

	next, err := plan.Next()
	if err != nil {
		return nil, multiErr(err, plan.Close())
	}

	docs := []map[string]interface{}{}
	docMap := plan.DocumentMap()

	for next {
		copy := docMap.ToMap(plan.Value())
		docs = append(docs, copy)

		next, err = plan.Next()
		if err != nil {
			return nil, multiErr(err, plan.Close())
		}
	}

	if err = plan.Close(); err != nil {
		return nil, err
	}

	return docs, err
}

// runRequest plans how to run the request, then attempts to run the request and returns the results.
func (p *Planner) runRequest(
	ctx context.Context,
	query *parser.Query,
) ([]map[string]interface{}, error) {
	plan, err := p.makePlan(query)

	if err != nil {
		return nil, err
	}

	isAnExplainRequest :=
		(len(query.Queries) > 0 && query.Queries[0].IsExplain) ||
			(len(query.Mutations) > 0 && query.Mutations[0].IsExplain)

	if isAnExplainRequest {
		return p.explainRequest(ctx, plan)
	}

	// This won't execute if it's an explain request.
	return p.executeRequest(ctx, plan)
}

// MakePlan makes a plan from the parsed query. @TODO {defradb/issues/368}: Test this exported function.
func (p *Planner) MakePlan(query *parser.Query) (planNode, error) {
	return p.makePlan(query)
}

// multiErr wraps all the non-nil errors and returns the wrapped error result.
func multiErr(errorsToWrap ...error) error {
	var errs error
	for _, err := range errorsToWrap {
		if err == nil {
			continue
		}
		if errs == nil {
			errs = fmt.Errorf("%w", err)
			continue
		}
		errs = fmt.Errorf("%s: %w", errs, err)
	}
	return errs
}
