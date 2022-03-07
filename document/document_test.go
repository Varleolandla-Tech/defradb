// Copyright 2022 Democratized Data Foundation
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
	"testing"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"

	"github.com/sourcenetwork/defradb/core"
	"github.com/sourcenetwork/defradb/document/key"
)

var (
	testJSONObj = []byte(`{
		"Name": "John",
		"Age": 26,
		"Address": {
			"Street": "Main",
			"City": "Toronto"
		}
	}`)

	pref = cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   mh.SHA2_256,
		MhLength: -1, // default length
	}
)

func TestNewFromJSON(t *testing.T) {
	doc, err := NewFromJSON(testJSONObj)
	if err != nil {
		t.Error("Error creating new doc from JSON:", err)
		return
	}

	buf, err := doc.Bytes()
	if err != nil {
		t.Error(err)
	}

	// And then feed it some data
	c, err := pref.Sum(buf)
	if err != nil {
		t.Error(err)
	}
	objKey := key.NewDocKeyV0(c)

	if objKey.String() != doc.Key().String() {
		t.Errorf("Incorrect doc key. Want %v, have %v", objKey.String(), doc.Key().String())
		return
	}

	// check field/value
	// fields
	assert.Equal(t, doc.fields["Name"].Name(), "Name")
	assert.Equal(t, doc.fields["Name"].Type(), core.LWW_REGISTER)
	assert.Equal(t, doc.fields["Age"].Name(), "Age")
	assert.Equal(t, doc.fields["Age"].Type(), core.LWW_REGISTER)
	assert.Equal(t, doc.fields["Address"].Name(), "Address")
	assert.Equal(t, doc.fields["Address"].Type(), core.OBJECT)

	//values
	assert.Equal(t, doc.values[doc.fields["Name"]].Value(), "John")
	assert.Equal(t, doc.values[doc.fields["Name"]].IsDocument(), false)
	assert.Equal(t, doc.values[doc.fields["Age"]].Value(), int64(26))
	assert.Equal(t, doc.values[doc.fields["Age"]].IsDocument(), false)
	assert.Equal(t, doc.values[doc.fields["Address"]].IsDocument(), true)

	//subdoc fields
	subDoc := doc.values[doc.fields["Address"]].Value().(*Document)
	assert.Equal(t, subDoc.fields["Street"].Name(), "Street")
	assert.Equal(t, subDoc.fields["Street"].Type(), core.LWW_REGISTER)
	assert.Equal(t, subDoc.fields["City"].Name(), "City")
	assert.Equal(t, subDoc.fields["City"].Type(), core.LWW_REGISTER)

	//subdoc values
	assert.Equal(t, subDoc.values[subDoc.fields["Street"]].Value(), "Main")
	assert.Equal(t, subDoc.values[subDoc.fields["Street"]].IsDocument(), false)
	assert.Equal(t, subDoc.values[subDoc.fields["City"]].Value(), "Toronto")
}

func TestSetWithJSON(t *testing.T) {
	doc, err := NewFromJSON(testJSONObj)
	if err != nil {
		t.Error("Error creating new doc from JSON:", err)
		return
	}

	buf, err := doc.Bytes()
	if err != nil {
		t.Error(err)
	}

	// And then feed it some data
	c, err := pref.Sum(buf)
	if err != nil {
		t.Error(err)
	}
	objKey := key.NewDocKeyV0(c)

	if objKey.String() != doc.Key().String() {
		t.Errorf("Incorrect doc key. Want %v, have %v", objKey.String(), doc.Key().String())
		return
	}

	updatePatch := []byte(`{
		"Name": "Alice",
		"Age": 27,
		"Address": null
	}`)
	err = doc.SetWithJSON(updatePatch)
	if err != nil {
		t.Error(err)
	}

	// check field/value
	// fields
	assert.Equal(t, doc.fields["Name"].Name(), "Name")
	assert.Equal(t, doc.fields["Name"].Type(), core.LWW_REGISTER)
	assert.Equal(t, doc.fields["Age"].Name(), "Age")
	assert.Equal(t, doc.fields["Age"].Type(), core.LWW_REGISTER)
	assert.Equal(t, doc.fields["Address"].Name(), "Address")
	assert.Equal(t, doc.fields["Address"].Type(), core.OBJECT)

	//values
	assert.Equal(t, doc.values[doc.fields["Name"]].Value(), "Alice")
	assert.Equal(t, doc.values[doc.fields["Name"]].IsDocument(), false)
	assert.Equal(t, doc.values[doc.fields["Age"]].Value(), int64(27))
	assert.Equal(t, doc.values[doc.fields["Age"]].IsDocument(), false)
	assert.Equal(t, doc.values[doc.fields["Address"]].IsDelete(), true)

	//subdoc fields
	// subDoc := doc.values[doc.fields["Address"]].Value().(*Document)
	// assert.Equal(t, subDoc.fields["Street"].Name(), "Street")
	// assert.Equal(t, subDoc.fields["Street"].Type(), core.LWW_REGISTER)
	// assert.Equal(t, subDoc.fields["City"].Name(), "City")
	// assert.Equal(t, subDoc.fields["City"].Type(), core.LWW_REGISTER)

	// //subdoc values
	// assert.Equal(t, subDoc.values[subDoc.fields["Street"]].Value(), "Main")
	// assert.Equal(t, subDoc.values[subDoc.fields["Street"]].IsDocument(), false)
	// assert.Equal(t, subDoc.values[subDoc.fields["City"]].Value(), "Toronto")
}
