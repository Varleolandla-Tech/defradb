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
	"math/rand"

	"github.com/sourcenetwork/defradb/client"
	"github.com/sourcenetwork/defradb/client/request"
)

const (
	defaultNumDocs           = 10
	defaultNumChildrenPerDoc = 2

	defaultStrLen = 10
	defaultIntMin = 0
	defaultIntMax = 10000
)

type (
	doc = map[string]any

	docRec struct {
		doc    doc
		docKey string
	}

	configsMap = map[tStr]map[fStr]genConfig
)

func AutoGenerateDocs(schema string, colName string, count int) []GeneratedDoc {
	parser := schemaParser{}
	typeDefs, genConfigs := parser.Parse(schema)
	generator := randomDocGenerator{types: typeDefs, config: genConfigs}
	return generator.GenerateDocs(colName, count)
}

type relationUsage struct {
	index          int
	minAmount      int
	maxAmount      int
	docKeysCounter []struct {
		ind   int
		count int
	}
	numDocs int
}

func newRelationUsage(minAmount, maxAmount, numDocs int) relationUsage {
	docKeysCounter := make([]struct {
		ind   int
		count int
	}, numDocs)
	for i := range docKeysCounter {
		docKeysCounter[i].ind = i
	}
	return relationUsage{
		minAmount:      minAmount,
		maxAmount:      maxAmount,
		numDocs:        numDocs,
		docKeysCounter: docKeysCounter,
	}
}

func (u *relationUsage) useNextDocKey() int {
	docKeyCounterInd := 0
	if u.index >= u.minAmount*u.numDocs {
		docKeyCounterInd = rand.Intn(len(u.docKeysCounter))
	} else {
		docKeyCounterInd = u.index % len(u.docKeysCounter)
	}
	currentInd := u.docKeysCounter[docKeyCounterInd].ind
	counter := &u.docKeysCounter[docKeyCounterInd]
	counter.count++
	if counter.count >= u.maxAmount {
		lastCounterInd := len(u.docKeysCounter) - 1
		*counter = u.docKeysCounter[lastCounterInd]
		u.docKeysCounter = u.docKeysCounter[:lastCounterInd]
	}
	u.index++

	return currentInd
}

type randomDocGenerator struct {
	types      map[tStr]typeDefinition
	config     configsMap
	resultDocs []GeneratedDoc
	counter    map[tStr]map[tStr]map[fStr]relationUsage
	cols       map[tStr][]docRec
	docsDemand map[tStr]int
}

func (g *randomDocGenerator) GenerateDocs(colName string, count int) []GeneratedDoc {
	g.resultDocs = make([]GeneratedDoc, 0, count)
	g.counter = make(map[tStr]map[tStr]map[fStr]relationUsage)
	g.cols = make(map[tStr][]docRec)
	g.docsDemand = make(map[tStr]int)

	primaryGraph, secondaryGraph := getRelationGraphs(g.types)
	order := getTopologicalOrder(primaryGraph, g.types)
	g.docsDemand[colName] = count
	g.calculateDocsDemand(order, primaryGraph, secondaryGraph)

	docsLists := g.generateRandomDocs(order)
	for _, docsList := range docsLists {
		typeDef := g.types[docsList.ColName]
		for _, doc := range docsList.Docs {
			g.resultDocs = append(g.resultDocs, GeneratedDoc{
				ColIndex: typeDef.index,
				JSON:     createDocJSON(doc),
			})
		}
	}
	return g.resultDocs
}

func (g *randomDocGenerator) getNextPrimaryDocKey(secondaryType tStr, field fieldDefinition) string {
	primaryType := field.typeStr
	current := g.counter[primaryType][secondaryType][field.name]

	ind := current.useNextDocKey()

	docKey := g.cols[primaryType][ind].docKey
	g.counter[primaryType][secondaryType][field.name] = current
	return docKey
}

func (g *randomDocGenerator) getDocKey(doc map[string]any) string {
	clientDoc, err := client.NewDocFromJSON([]byte(createDocJSON(doc)))
	if err != nil {
		panic("failed to create doc from JSON: " + err.Error())
	}
	return clientDoc.Key().String()
}

func (g *randomDocGenerator) generateRandomDocs(order []tStr) []DocsList {
	result := []DocsList{}
	for _, typeName := range order {
		col := DocsList{ColName: typeName}
		typeDef := g.types[typeName]

		currentTypeDemand := g.docsDemand[typeName]
		for i := 0; i < currentTypeDemand; i++ {
			newDoc := make(doc)
			for _, field := range typeDef.fields {
				if field.isRelation {
					if field.isPrimary {
						newDoc[field.name+request.RelatedObjectID] = g.getNextPrimaryDocKey(typeName, field)
					}
				} else {
					newDoc[field.name] = g.generateRandomValue(field.typeStr, g.getFieldConfig(typeName, field.name))
				}
			}
			g.cols[typeName] = append(g.cols[typeName], docRec{doc: newDoc, docKey: g.getDocKey(newDoc)})
			col.Docs = append(col.Docs, newDoc)
		}
		result = append(result, col)
	}
	return result
}

func (g *randomDocGenerator) getFieldConfig(typeStr, fieldName string) genConfig {
	var fieldConfig genConfig
	typeConfig := g.config[typeStr]
	if typeConfig != nil {
		fieldConfig = typeConfig[fieldName]
	}
	return fieldConfig
}

func getMinMaxOrDefault[T int | float64](conf genConfig, min, max T) (T, T) {
	if prop, ok := conf.props["min"]; ok {
		min = prop.(T)
	}
	if prop, ok := conf.props["max"]; ok {
		max = prop.(T)
	}
	return min, max
}

func (g *randomDocGenerator) generateRandomValue(typeStr string, fieldConfig genConfig) any {
	switch typeStr {
	case "String":
		strLen := defaultStrLen
		if prop, ok := fieldConfig.props["len"]; ok {
			strLen = prop.(int)
		}
		return getRandomString(strLen)
	case "Int":
		min, max := getMinMaxOrDefault(fieldConfig, defaultIntMin, defaultIntMax)
		return min + rand.Intn(max-min+1)
	case "Boolean":
		return rand.Float32() < 0.5
	case "Float":
		min, max := getMinMaxOrDefault(fieldConfig, 0.0, 1.0)
		return min + rand.Float64()*(max-min)
	}
	panic("Can not generate random value for unknown type: " + typeStr)
}

func (g *randomDocGenerator) initRelationUsages(secondaryType, primaryType string, min, max int) {
	secondaryTypeDef := g.types[secondaryType]
	for _, secondaryTypeField := range secondaryTypeDef.fields {
		if secondaryTypeField.typeStr == primaryType {
			g.addRelationUsage(secondaryType, secondaryTypeField, min, max)
		}
	}
}

func (g *randomDocGenerator) addRelationUsage(secondaryType string, field fieldDefinition, min, max int) {
	primaryType := field.typeStr
	if _, ok := g.counter[primaryType]; !ok {
		g.counter[primaryType] = make(map[tStr]map[fStr]relationUsage)
	}
	if _, ok := g.counter[primaryType][secondaryType]; !ok {
		g.counter[primaryType][secondaryType] = make(map[fStr]relationUsage)
	}
	if _, ok := g.counter[primaryType][secondaryType][field.name]; !ok {
		g.counter[primaryType][secondaryType][field.name] = newRelationUsage(
			min, max, g.docsDemand[primaryType])
	}
}
