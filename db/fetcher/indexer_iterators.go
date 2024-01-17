// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package fetcher

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
	ds "github.com/ipfs/go-datastore"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/connor"
	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/datastore"
	"github.com/sourcenetwork/defradb/planner/mapper"

	"github.com/ipfs/go-datastore/query"
)

const (
	opEq    = "_eq"
	opGt    = "_gt"
	opGe    = "_ge"
	opLt    = "_lt"
	opLe    = "_le"
	opNe    = "_ne"
	opIn    = "_in"
	opNin   = "_nin"
	opLike  = "_like"
	opNlike = "_nlike"
	opAny   = "_any"
)

// indexIterator is an iterator over index keys.
// It is used to iterate over the index keys that match a specific condition.
// For example, iteration over condition _eq and _gt will have completely different logic.
type indexIterator interface {
	Init(context.Context, datastore.DSReaderWriter) error
	Next() (indexIterResult, error)
	Close() error
}

type indexIterResult struct {
	key      core.IndexDataStoreKey
	foundKey bool
	value    []byte
}

type queryResultIterator struct {
	resultIter query.Results
}

func (i *queryResultIterator) Next() (indexIterResult, error) {
	res, hasVal := i.resultIter.NextSync()
	if res.Error != nil {
		return indexIterResult{}, res.Error
	}
	if !hasVal {
		return indexIterResult{}, nil
	}
	key, err := core.NewIndexDataStoreKey(res.Key)
	if err != nil {
		return indexIterResult{}, err
	}
	return indexIterResult{key: key, value: res.Value, foundKey: true}, nil
}

func (i *queryResultIterator) Close() error {
	return i.resultIter.Close()
}

type eqPrefixIndexIterator struct {
	indexKey      core.IndexDataStoreKey
	keyFieldValue []byte
	execInfo      *ExecInfo
	matchers      []valueMatcher

	queryResultIterator
}

func (i *eqPrefixIndexIterator) Init(ctx context.Context, store datastore.DSReaderWriter) error {
	i.indexKey.FieldValues = [][]byte{i.keyFieldValue}
	resultIter, err := store.Query(ctx, query.Query{
		Prefix: i.indexKey.ToString(),
	})
	if err != nil {
		return err
	}
	i.resultIter = resultIter
	return nil
}

func (i *eqPrefixIndexIterator) Next() (indexIterResult, error) {
	for {
		res, err := i.queryResultIterator.Next()
		if err != nil || !res.foundKey {
			return res, err
		}
		i.execInfo.IndexesFetched++
		doesMatch, err := executeValueMatchers(i.matchers, res.key.FieldValues)
		if err != nil {
			return indexIterResult{}, err
		}
		if !doesMatch {
			continue
		}
		return res, err
	}
}

type eqSingleIndexIterator struct {
	indexKey       core.IndexDataStoreKey
	keyFieldValues [][]byte
	execInfo       *ExecInfo

	ctx   context.Context
	store datastore.DSReaderWriter
}

func (i *eqSingleIndexIterator) SetKeyFieldValue(value []byte) {
	i.keyFieldValues = [][]byte{value}
}

func (i *eqSingleIndexIterator) Init(ctx context.Context, store datastore.DSReaderWriter) error {
	i.ctx = ctx
	i.store = store
	return nil
}

func (i *eqSingleIndexIterator) Next() (indexIterResult, error) {
	if i.store == nil {
		return indexIterResult{}, nil
	}
	i.indexKey.FieldValues = i.keyFieldValues
	val, err := i.store.Get(i.ctx, i.indexKey.ToDS())
	if err != nil {
		if errors.Is(err, ds.ErrNotFound) {
			return indexIterResult{key: i.indexKey}, nil
		}
		return indexIterResult{}, err
	}
	i.store = nil
	i.execInfo.IndexesFetched++
	return indexIterResult{key: i.indexKey, value: val, foundKey: true}, nil
}

func (i *eqSingleIndexIterator) Close() error {
	return nil
}

type inIndexIterator struct {
	indexIterator
	keyFieldValues [][]byte
	nextValIndex   int
	ctx            context.Context
	store          datastore.DSReaderWriter
	hasIterator    bool
}

func (i *inIndexIterator) nextIterator() (bool, error) {
	if i.nextValIndex > 0 {
		err := i.indexIterator.Close()
		if err != nil {
			return false, err
		}
	}

	if i.nextValIndex >= len(i.keyFieldValues) {
		return false, nil
	}

	switch fieldIter := i.indexIterator.(type) {
	case *eqPrefixIndexIterator:
		fieldIter.keyFieldValue = i.keyFieldValues[i.nextValIndex]
	case *eqSingleIndexIterator:
		fieldIter.keyFieldValues[0] = i.keyFieldValues[i.nextValIndex]
	}
	err := i.indexIterator.Init(i.ctx, i.store)
	if err != nil {
		return false, err
	}
	i.nextValIndex++
	return true, nil
}

func (i *inIndexIterator) Init(ctx context.Context, store datastore.DSReaderWriter) error {
	i.ctx = ctx
	i.store = store
	var err error
	i.hasIterator, err = i.nextIterator()
	return err
}

func (i *inIndexIterator) Next() (indexIterResult, error) {
	for i.hasIterator {
		res, err := i.indexIterator.Next()
		if err != nil {
			return indexIterResult{}, err
		}
		if !res.foundKey {
			i.hasIterator, err = i.nextIterator()
			if err != nil {
				return indexIterResult{}, err
			}
			continue
		}
		return res, nil
	}
	return indexIterResult{}, nil
}

func (i *inIndexIterator) Close() error {
	return nil
}

type errorCheckingFilter struct {
	matchers []valueMatcher
	err      error
	execInfo *ExecInfo
}

func executeValueMatchers(matchers []valueMatcher, values [][]byte) (bool, error) {
	for i := range matchers {
		res, err := matchers[i].Match(values[i])
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
	}
	return true, nil
}

func (f *errorCheckingFilter) Filter(e query.Entry) bool {
	if f.err != nil {
		return false
	}
	f.execInfo.IndexesFetched++

	indexKey, err := core.NewIndexDataStoreKey(e.Key)
	if err != nil {
		f.err = err
		return false
	}

	var res bool
	res, f.err = executeValueMatchers(f.matchers, indexKey.FieldValues)
	return res
}

type scanningIndexIterator struct {
	queryResultIterator
	indexKey core.IndexDataStoreKey
	matchers []valueMatcher
	filter   errorCheckingFilter
	execInfo *ExecInfo
}

func (i *scanningIndexIterator) Init(ctx context.Context, store datastore.DSReaderWriter) error {
	i.filter.matchers = i.matchers
	i.filter.execInfo = i.execInfo

	iter, err := store.Query(ctx, query.Query{
		Prefix:  i.indexKey.ToString(),
		Filters: []query.Filter{&i.filter},
	})
	if err != nil {
		return err
	}
	i.resultIter = iter

	return nil
}

func (i *scanningIndexIterator) Next() (indexIterResult, error) {
	res, err := i.queryResultIterator.Next()
	if i.filter.err != nil {
		return indexIterResult{}, i.filter.err
	}
	return res, err
}

// checks if the value satisfies the condition
type valueMatcher interface {
	Match([]byte) (bool, error)
}

// indexByteValuesMatcher is a filter that compares the index value with a given value.
// It uses bytes.Compare to compare the values and evaluate the result with evalFunc.
type indexByteValuesMatcher struct {
	value []byte
	// evalFunc receives a result of bytes.Compare
	evalFunc func(int) bool
}

func (m *indexByteValuesMatcher) Match(value []byte) (bool, error) {
	res := bytes.Compare(value, m.value)
	return m.evalFunc(res), nil
}

// checks if the index value is or is not in the given array
type indexInArrayMatcher struct {
	values map[string]bool
	isIn   bool
}

func newNinIndexCmp(values [][]byte, isIn bool) *indexInArrayMatcher {
	valuesMap := make(map[string]bool)
	for _, v := range values {
		valuesMap[string(v)] = true
	}
	return &indexInArrayMatcher{values: valuesMap, isIn: isIn}
}

func (m *indexInArrayMatcher) Match(value []byte) (bool, error) {
	_, found := m.values[string(value)]
	return found == m.isIn, nil
}

// checks if the index value satisfies the LIKE condition
type indexLikeMatcher struct {
	hasPrefix   bool
	hasSuffix   bool
	startAndEnd []string
	isLike      bool
	value       string
}

func newLikeIndexCmp(filterValue string, isLike bool) *indexLikeMatcher {
	matcher := &indexLikeMatcher{
		isLike: isLike,
	}
	if len(filterValue) >= 2 {
		if filterValue[0] == '%' {
			matcher.hasPrefix = true
			filterValue = strings.TrimPrefix(filterValue, "%")
		}
		if filterValue[len(filterValue)-1] == '%' {
			matcher.hasSuffix = true
			filterValue = strings.TrimSuffix(filterValue, "%")
		}
		if !matcher.hasPrefix && !matcher.hasSuffix {
			matcher.startAndEnd = strings.Split(filterValue, "%")
		}
	}
	matcher.value = filterValue

	return matcher
}

func (m *indexLikeMatcher) Match(value []byte) (bool, error) {
	var currentVal string
	err := cbor.Unmarshal(value, &currentVal)
	if err != nil {
		return false, err
	}

	return m.doesMatch(currentVal) == m.isLike, nil
}

func (m *indexLikeMatcher) doesMatch(currentVal string) bool {
	switch {
	case m.hasPrefix && m.hasSuffix:
		return strings.Contains(currentVal, m.value)
	case m.hasPrefix:
		return strings.HasSuffix(currentVal, m.value)
	case m.hasSuffix:
		return strings.HasPrefix(currentVal, m.value)
	// there might be 2 ends only for LIKE with 1 % in the middle "ab%cd"
	case len(m.startAndEnd) == 2:
		return strings.HasPrefix(currentVal, m.startAndEnd[0]) &&
			strings.HasSuffix(currentVal, m.startAndEnd[1])
	default:
		return m.value == currentVal
	}
}

type anyMatcher struct{}

func (m *anyMatcher) Match([]byte) (bool, error) { return true, nil }

func createValueMatcher(op string, filterVal any) (valueMatcher, error) {
	switch op {
	case opEq, opGt, opGe, opLt, opLe, opNe:
		fieldValue := client.NewFieldValue(client.LWW_REGISTER, filterVal)

		valueBytes, err := fieldValue.Bytes()
		if err != nil {
			return nil, err
		}

		m := &indexByteValuesMatcher{value: valueBytes}
		switch op {
		case opEq:
			m.evalFunc = func(res int) bool { return res == 0 }
		case opGt:
			m.evalFunc = func(res int) bool { return res > 0 }
		case opGe:
			m.evalFunc = func(res int) bool { return res > 0 || res == 0 }
		case opLt:
			m.evalFunc = func(res int) bool { return res < 0 }
		case opLe:
			m.evalFunc = func(res int) bool { return res < 0 || res == 0 }
		case opNe:
			m.evalFunc = func(res int) bool { return res != 0 }
		}
		return m, nil
	case opIn, opNin:
		inArr, ok := filterVal.([]any)
		if !ok {
			return nil, errors.New("invalid _in/_nin value")
		}
		valArr := make([][]byte, 0, len(inArr))
		for _, v := range inArr {
			fieldValue := client.NewFieldValue(client.LWW_REGISTER, v)
			valueBytes, err := fieldValue.Bytes()
			if err != nil {
				return nil, err
			}
			valArr = append(valArr, valueBytes)
		}
		return newNinIndexCmp(valArr, op == opIn), nil
	case opLike, opNlike:
		return newLikeIndexCmp(filterVal.(string), op == opLike), nil
	case opAny:
		return &anyMatcher{}, nil
	}

	return nil, errors.New("invalid index filter condition")
}

func createValueMatchers(conditions []fieldFilterCond) ([]valueMatcher, error) {
	matchers := make([]valueMatcher, 0, len(conditions))
	for i := range conditions {
		m, err := createValueMatcher(conditions[i].op, conditions[i].val)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

type fieldFilterCond struct {
	op  string
	val any
}

func (f *IndexFetcher) determineFieldFilterConditions() []fieldFilterCond {
	result := make([]fieldFilterCond, 0, len(f.indexedFields))
	for i := range f.indexedFields {
		fieldInd := f.mapping.FirstIndexOfName(f.indexedFields[i].Name)
		found := false
		for filterKey, indexFilterCond := range f.indexFilter.Conditions {
			propKey, ok := filterKey.(*mapper.PropertyIndex)
			if !ok {
				continue
			}
			if fieldInd != propKey.Index {
				continue
			}

			found = true

			condMap := indexFilterCond.(map[connor.FilterKey]any)
			for key, filterVal := range condMap {
				opKey := key.(*mapper.Operator)
				result = append(result, fieldFilterCond{op: opKey.Operation, val: filterVal})
				break
			}
			break
		}
		if !found {
			result = append(result, fieldFilterCond{op: opAny})
		}
	}
	return result
}

func isUniqueFetchByFullKey(indexDesc *client.IndexDescription, conditions []fieldFilterCond) bool {
	res := indexDesc.Unique && len(conditions) == len(indexDesc.Fields)
	for i := 1; i < len(conditions); i++ {
		res = res && conditions[i].op == opEq
	}
	return res
}

func getFieldsBytes(conditions []fieldFilterCond) ([][]byte, error) {
	result := make([][]byte, 0, len(conditions))
	for i := range conditions {
		fieldVal := client.NewFieldValue(client.LWW_REGISTER, conditions[i].val)
		keyFieldBytes, err := fieldVal.Bytes()
		if err != nil {
			return nil, err
		}
		result = append(result, keyFieldBytes)
	}
	return result, nil
}

func (f *IndexFetcher) createIndexIterator() (indexIterator, error) {
	fieldConditions := f.determineFieldFilterConditions()
	indexDataStoreKey := core.IndexDataStoreKey{CollectionID: f.col.ID(), IndexID: f.indexDesc.ID}

	matchers, err := createValueMatchers(fieldConditions)
	if err != nil {
		return nil, err
	}

	switch fieldConditions[0].op {
	case opEq:
		if isUniqueFetchByFullKey(&f.indexDesc, fieldConditions) {
			keyFieldsBytes, err := getFieldsBytes(fieldConditions)
			if err != nil {
				return nil, err
			}
			return &eqSingleIndexIterator{
				indexKey:       indexDataStoreKey,
				keyFieldValues: keyFieldsBytes,
				execInfo:       &f.execInfo,
			}, nil
		} else {
			fieldVal := client.NewFieldValue(client.LWW_REGISTER, fieldConditions[0].val)

			keyValueBytes, err := fieldVal.Bytes()
			if err != nil {
				return nil, err
			}

			// iterators for _eq filter already iterate over keys with first field value
			// matching the filter value, so we can skip the first matcher
			if len(matchers) > 1 {
				matchers[0] = &anyMatcher{}
			}

			return &eqPrefixIndexIterator{
				indexKey:      indexDataStoreKey,
				keyFieldValue: keyValueBytes,
				execInfo:      &f.execInfo,
				matchers:      matchers,
			}, nil
		}
	case opIn:
		inArr, ok := fieldConditions[0].val.([]any)
		if !ok {
			return nil, errors.New("invalid _in/_nin value")
		}
		keyFieldArr := make([][]byte, 0, len(inArr))
		for _, v := range inArr {
			fieldVal := client.NewFieldValue(client.LWW_REGISTER, v)
			keyFieldBytes, err := fieldVal.Bytes()
			if err != nil {
				return nil, err
			}
			keyFieldArr = append(keyFieldArr, keyFieldBytes)
		}

		// iterators for _in filter already iterate over keys with first field value
		// matching the filter value, so we can skip the first matcher
		if len(matchers) > 1 {
			matchers[0] = &anyMatcher{}
		}

		var iter indexIterator
		if isUniqueFetchByFullKey(&f.indexDesc, fieldConditions) {
			restFieldsVals, e := getFieldsBytes(fieldConditions[1:])
			if e != nil {
				return nil, e
			}
			restFieldsVals = append([][]byte{{}}, restFieldsVals...)
			iter = &eqSingleIndexIterator{
				indexKey:       indexDataStoreKey,
				execInfo:       &f.execInfo,
				keyFieldValues: restFieldsVals,
			}
		} else {
			iter = &eqPrefixIndexIterator{
				indexKey: indexDataStoreKey,
				execInfo: &f.execInfo,
				matchers: matchers,
			}
		}
		return &inIndexIterator{
			indexIterator:  iter,
			keyFieldValues: keyFieldArr,
		}, nil
	case opGt, opGe, opLt, opLe, opNe, opNin, opLike, opNlike:
		return &scanningIndexIterator{
			indexKey: indexDataStoreKey,
			matchers: matchers,
			execInfo: &f.execInfo,
		}, nil
	}

	return nil, errors.New("invalid index filter condition")
}
