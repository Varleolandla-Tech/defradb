// Copyright 2020 Source Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.
package document

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"

	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/db/base"
	"github.com/sourcenetwork/defradb/document/key"
)

// This is the main implementation stating point for accessing the internal Document API
// Which provides API access to the various operations available for Documents
// IE. CRUD.
//
// Documents in this case refer to the core database type of DefraDB which is a
// "NoSQL Document Datastore"
//
// This section is not concerned with the outer query layer used to interact with the
// Document API, but instead is soley consered with carrying out the internal API
// operations. IE. CRUD.
//
// Note: These actions on the outside are deceivingly simple, but require a number
// of complex interactions with the underlying KV Datastore, as well as the
// Merkle CRDT semantics.

// errors
var (
	ErrFieldNotExist     = errors.New("The given field does not exist")
	ErrFieldNotObject    = errors.New("Trying to access field on a non object type")
	ErrValueTypeMismatch = errors.New("Value does not match indicated type")
)

// Document is a generalized struct referring to a stored document in the database.
//
// It *can* have a reference to a enforced schema, which is enforced at the time
// of an operation.
//
// Documents are similar to JSON Objects stored in MongoDB, which are collections
// of Fields and Values.
// Fields are Key names that point to values
// Values are literal or complex objects such as strings, integers, or sub documents (objects)
//
// Note: Documents represent the serialized state of the underlying MerkleCRDTs
//
// @todo: Extract Document into a Interface
// @body: A document interface can be implemented by both a TypedDocument and a
// UnTypedDocument, which use a schema and schemaless approach respectively.
type Document struct {
	schema base.SchemaDescription
	key    key.DocKey
	fields map[string]Field
	values map[Field]Value
	// @TODO: schemaInfo schema.Info

	// marks if document has unsaved changes
	isDirty bool
}

// New returns a newly instanciated Document
func New() *Document {
	return newEmptyDoc()
}

func NewWithKey(key key.DocKey) *Document {
	doc := newEmptyDoc()
	doc.key = key
	return doc
}

func newEmptyDoc() *Document {
	return &Document{
		fields: make(map[string]Field),
		values: make(map[Field]Value),
	}
}

func NewFromMap(data map[string]interface{}, schema ...base.SchemaDescription) (*Document, error) {
	var err error
	doc := &Document{
		fields: make(map[string]Field),
		values: make(map[Field]Value),
	}

	if len(schema) > 0 {
		doc.schema = schema[0]
	}

	// check if document contains special _key field
	k, hasKey := data["_key"]
	if hasKey {
		delete(data, "_key") // remove the key so it isn't parsed further
		kstr, ok := k.(string)
		if !ok {
			return nil, errors.New("Provided _key in document must be a string type")
		}
		if doc.key, err = key.NewFromString(kstr); err != nil {
			return nil, err
		}
	}

	err = doc.setAndParseObjectType(data)
	if err != nil {
		return nil, err
	}

	// if no key was specified, then we assume it doesn't exist and we generate it.
	if !hasKey {
		pref := cid.Prefix{
			Version:  1,
			Codec:    cid.Raw,
			MhType:   mh.SHA2_256,
			MhLength: -1, // default length
		}

		buf, err := doc.Bytes()
		if err != nil {
			return nil, err
		}

		// And then feed it some data
		c, err := pref.Sum(buf)
		if err != nil {
			return nil, err
		}
		// fmt.Println(c)
		doc.key = key.NewDocKeyV0(c)
	}

	return doc, nil
}

// NewFromJSON creates a new instance of a Document from a raw JSON object byte array
func NewFromJSON(obj []byte, schema ...base.SchemaDescription) (*Document, error) {
	data := make(map[string]interface{})
	err := json.Unmarshal(obj, &data)
	if err != nil {
		return nil, err
	}

	return NewFromMap(data, schema...)
}

// Key returns the generated DocKey for this document
func (doc *Document) Key() key.DocKey {
	return doc.key
}

// Get returns the raw value for a given field
// Since Documents are objects with potentially sub objects
// a supplied field string can be of the form "A/B/C"
// Where field A is an object containing a object B which has
// a field C
// If no matching field exists then return an empty interface
// and an error.
func (doc *Document) Get(field string) (interface{}, error) {
	val, err := doc.GetValue(field)
	if err != nil {
		return nil, err
	}
	return val.Value(), nil
}

// GetValue given a field as a string, return the Value type
func (doc *Document) GetValue(field string) (Value, error) {
	path, subPaths, hasSubPaths := parseFieldPath(field)
	f, exists := doc.fields[path]
	if !exists {
		return nil, ErrFieldNotExist
	}

	val, err := doc.GetValueWithField(f)
	if err != nil {
		return nil, err
	}

	if !hasSubPaths {
		return val, nil
	} else if hasSubPaths && !val.IsDocument() {
		return nil, ErrFieldNotObject
	} else {
		return val.Value().(*Document).GetValue(subPaths)
	}
}

// GetValueWithField gets the Value type from a given Field type
func (doc *Document) GetValueWithField(f Field) (Value, error) {
	v, exists := doc.values[f]
	if !exists {
		return nil, ErrFieldNotExist
	}
	return v, nil
}

// SetWithJSON sets all the fields of a document using the provided
// JSON Merge Patch object. Note: fields indicated as nil in the Merge
// Patch are to be deleted
// @todo: Handle sub documents for SetWithJSON
func (doc *Document) SetWithJSON(patch []byte) error {
	var patchObj map[string]interface{}
	err := json.Unmarshal(patch, &patchObj)
	if err != nil {
		return err
	}

	for k, v := range patchObj {
		fmt.Println(k, v)
		if v == nil { // needs deletion
			err = doc.Delete(k)
		} else {
			err = doc.Set(k, v)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Set the value of a field
func (doc *Document) Set(field string, value interface{}) error {
	return doc.setAndParseType(field, value)
}

// SetAs is the same as set, but you can manually set the CRDT type
func (doc *Document) SetAs(field string, value interface{}, t core.CType) error {
	return doc.setCBOR(t, field, value)
}

// Delete removes a field, and marks it to be deleted on the following db.Update() call
func (doc *Document) Delete(fields ...string) error {
	for _, f := range fields {
		field, exists := doc.fields[f]
		if !exists {
			return ErrFieldNotExist
		}

		val := doc.values[field]
		val.Delete()
	}
	return nil
}

// SetAsType Sets the value of a field along with a specific type
// func (doc *Document) SetAsType(t core.CType, field string, value interface{}) error {
// 	return doc.set(t, field, value)
// }

// set implementation
// @todo Apply locking on  Document field/value operations
func (doc *Document) set(t core.CType, field string, value Value) error {
	var f Field
	if v, exists := doc.fields[field]; exists {
		f = v
	} else {
		f = doc.newField(t, field)
		doc.fields[field] = f
	}
	doc.values[f] = value
	doc.isDirty = true
	return nil
}

func (doc *Document) setCBOR(t core.CType, field string, val interface{}) error {
	value := newCBORValue(t, val)
	return doc.set(t, field, value)
}

/* Comment the following functions as they aren't used anywhere to satisfy the linter:

func (doc *Document) setString(t core.CType, field string, val string) error {
	value := NewStringValue(t, val)
	return doc.set(t, field, value)
}

func (doc *Document) setInt64(t core.CType, field string, val int64) error {
	value := NewInt64Value(t, val)
	return doc.set(t, field, value)
}

*/

func (doc *Document) setObject(t core.CType, field string, val *Document) error {
	value := newValue(t, val)
	return doc.set(t, field, &value)
}

func (doc *Document) setAndParseType(field string, value interface{}) error {
	switch val := value.(type) { // nolint:gosimple @todo fix this linter error,

	// int (any number)
	case float64:
		// case int64:

		// Check if its actually a float or just an int
		if float64(int64(val)) == val { //int
			doc.setCBOR(core.LWW_REGISTER, field, int64(val))
		} else { //float
			doc.setCBOR(core.LWW_REGISTER, field, val)
		}
		/* Redundant break statement (S1023), linter screams.
		break
		*/

	// string, bool, and more
	case string, bool:
		doc.setCBOR(core.LWW_REGISTER, field, val)
		/* Redundant break statement (S1023), linter screams.
		break
		*/

	// array
	case []interface{}:
		break

	// sub object, recurse down.
	// @TODO: Object Definitions
	// You can use an object as a way to override defults
	// and types for JSON literals.
	// Eg.
	// Instead of { "Timestamp": 123 }
	//			- which is parsed as an int
	// Use { "Timestamp" : { "_Type": "uint64", "_Value": 123 } }
	//			- Which is parsed as an uint64
	case map[string]interface{}:
		subDoc := newEmptyDoc()
		err := subDoc.setAndParseObjectType(val)
		if err != nil {
			return err
		}

		doc.setObject(core.OBJECT, field, subDoc)
		/* Redundant break statement (S1023), linter screams.
		break
		*/

	default:
		return fmt.Errorf("Unhandled type in raw JSON: %v => %T", field, val)

	}
	return nil
}

func (doc *Document) setAndParseObjectType(value map[string]interface{}) error {
	for k, v := range value {
		err := doc.setAndParseType(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// Fields gets the document fields as a map
func (doc *Document) Fields() map[string]Field {
	return doc.fields
}

// Values gets the document values as a map
func (doc *Document) Values() map[Field]Value {
	return doc.values
}

// Bytes returns the document as a serialzed byte array
// using CBOR encoding
func (doc *Document) Bytes() ([]byte, error) {
	docMap, err := doc.toMap()
	if err != nil {
		return nil, err
	}

	// Important: CannonicalEncOpionts ensures consistent serialization of
	// indeterministic datastructures, like Go Maps
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(docMap)
}

// String returns the document as a strinified JSON Object.
// Note: This representation should not be used for any
// cryptographic operations, such as signatures, or hashes
// as it does not gurantee cannonical representation or
// ordering.
func (doc *Document) String() string {
	docMap, err := doc.toMap()
	if err != nil {
		panic(err) //should we return (string, error)?
	}

	j, err := json.MarshalIndent(docMap, "", "\t")
	if err != nil {
		panic(err) // same as above
	}
	return string(j)
}

// ToMap returns the document as a map[string]interface{}
// object.
func (doc *Document) ToMap() (map[string]interface{}, error) {
	return doc.toMapWithKey()
}

// converts the document into a map[string]interface{}
// including any sub documents
func (doc *Document) toMap() (map[string]interface{}, error) {
	docMap := make(map[string]interface{})
	for k, v := range doc.fields {
		value, exists := doc.values[v]
		if !exists {
			return nil, ErrFieldNotExist
		}

		if value.IsDocument() {
			subDoc := value.Value().(*Document)
			subDocMap, err := subDoc.toMap()
			if err != nil {
				return nil, err
			}
			docMap[k] = subDocMap
		} else {

		}
		docMap[k] = value.Value()
	}

	return docMap, nil
}

func (doc *Document) toMapWithKey() (map[string]interface{}, error) {
	docMap := make(map[string]interface{})
	for k, v := range doc.fields {
		value, exists := doc.values[v]
		if !exists {
			return nil, ErrFieldNotExist
		}

		if value.IsDocument() {
			subDoc := value.Value().(*Document)
			subDocMap, err := subDoc.toMapWithKey()
			if err != nil {
				return nil, err
			}
			docMap[k] = subDocMap
		} else {

		}
		docMap[k] = value.Value()
	}
	docMap["_key"] = doc.Key().String()

	return docMap, nil
}

// loops through an object of the form map[string]interface{}
// and fills in the Document with each field it finds in the object.
// Automatically handles sub objects and arrays.
// Does not allow anonymous fields, error is thrown in this case
// Eg. The JSON value [1,2,3,4] by itself is a valid JSON Object, but has no
// field name.
// func parseJSONObject(doc *Document, data map[string]interface{}) error {
// 	for k, v := range data {
// 		switch v.(type) {

// 		// int (any number)
// 		case float64:
// 			// case int64:

// 			// Check if its actually a float or just an int
// 			val := v.(float64)
// 			if float64(int64(val)) == val { //int
// 				doc.setCBOR(crdt.LWW_REGISTER, k, int64(val))
// 			} else { //float
// 				panic("todo")
// 			}
// 			break

// 		// string
// 		case string:
// 			doc.setCBOR(crdt.LWW_REGISTER, k, v)
// 			break

// 		// array
// 		case []interface{}:
// 			break

// 		// sub object, recurse down.
// 		// @TODO: Object Definitions
// 		// You can use an object as a way to override defults
// 		// and types for JSON literals.
// 		// Eg.
// 		// Instead of { "Timestamp": 123 }
// 		//			- which is parsed as an int
// 		// Use { "Timestamp" : { "_Type": "uint64", "_Value": 123 } }
// 		//			- Which is parsed as an uint64
// 		case map[string]interface{}:
// 			subDoc := newEmptyDoc()
// 			err := parseJSONObject(subDoc, v.(map[string]interface{}))
// 			if err != nil {
// 				return err
// 			}

// 			doc.setObject(crdt.OBJECT, k, subDoc)
// 			break

// 		default:
// 			return fmt.Errorf("Unhandled type in raw JSON: %v => %T", k, v)

// 		}
// 	}
// 	return nil
// }

// parses a document field path, can have sub elements if we have embedded objects.
// Returns the first path, the remaining split paths, and a bool indicating if there are sub paths
func parseFieldPath(path string) (string, string, bool) {
	splitKeys := strings.SplitN(path, "/", 2)
	return splitKeys[0], strings.Join(splitKeys[1:], ""), len(splitKeys) > 1
}

// Exmaple Usage: Create/Insert new object
/*

obj := `{
	Hello: "World"
}`
objData := make(map[string]interface{})
err := json.Unmarshal(&objData, obj)

docA := document.NewFromJSON(objData)
err := db.Save(document)
		=> New batch transaction/store
		=> Loop through doc values
		=> 		instanciate MerkleCRDT objects
		=> 		Set/Publish new CRDT values


// One-to-one relatioship example
obj := `{
	Hello: "world",
	Author: {
		Name: "Bob",
	}
}`

docA := document.NewFromJSON(obj)

// method 1
docA.Patch(...)
col.Save(docA)

// method 2
docA.Get("Author").Set("Name", "Eric")
col.Save(docA)

// method 3
docB := docA.GetObject("Author")
docB.Set("Name", "Eric")
authorCollection.Save(docB)

// method 4
docA.Set("Author.Name")

// method 5
doc := col.GetWithRelations("key")
// equivalent
doc := col.Get(key, db.WithRelationsOpt)

*/
