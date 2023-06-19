// Code generated by mockery v2.26.1. DO NOT EDIT.

package mocks

import (
	client "github.com/sourcenetwork/defradb/client"
	core "github.com/sourcenetwork/defradb/core"

	mock "github.com/stretchr/testify/mock"
)

// EncodedDocument is an autogenerated mock type for the EncodedDocument type
type EncodedDocument struct {
	mock.Mock
}

type EncodedDocument_Expecter struct {
	mock *mock.Mock
}

func (_m *EncodedDocument) EXPECT() *EncodedDocument_Expecter {
	return &EncodedDocument_Expecter{mock: &_m.Mock}
}

// Decode provides a mock function with given fields:
func (_m *EncodedDocument) Decode() (*client.Document, error) {
	ret := _m.Called()

	var r0 *client.Document
	var r1 error
	if rf, ok := ret.Get(0).(func() (*client.Document, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *client.Document); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Document)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EncodedDocument_Decode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decode'
type EncodedDocument_Decode_Call struct {
	*mock.Call
}

// Decode is a helper method to define mock.On call
func (_e *EncodedDocument_Expecter) Decode() *EncodedDocument_Decode_Call {
	return &EncodedDocument_Decode_Call{Call: _e.mock.On("Decode")}
}

func (_c *EncodedDocument_Decode_Call) Run(run func()) *EncodedDocument_Decode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *EncodedDocument_Decode_Call) Return(_a0 *client.Document, _a1 error) *EncodedDocument_Decode_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *EncodedDocument_Decode_Call) RunAndReturn(run func() (*client.Document, error)) *EncodedDocument_Decode_Call {
	_c.Call.Return(run)
	return _c
}

// DecodeToDoc provides a mock function with given fields: _a0
func (_m *EncodedDocument) DecodeToDoc(_a0 *core.DocumentMapping) (core.Doc, error) {
	ret := _m.Called(_a0)

	var r0 core.Doc
	var r1 error
	if rf, ok := ret.Get(0).(func(*core.DocumentMapping) (core.Doc, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(*core.DocumentMapping) core.Doc); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(core.Doc)
	}

	if rf, ok := ret.Get(1).(func(*core.DocumentMapping) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EncodedDocument_DecodeToDoc_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DecodeToDoc'
type EncodedDocument_DecodeToDoc_Call struct {
	*mock.Call
}

// DecodeToDoc is a helper method to define mock.On call
//   - _a0 *core.DocumentMapping
func (_e *EncodedDocument_Expecter) DecodeToDoc(_a0 interface{}) *EncodedDocument_DecodeToDoc_Call {
	return &EncodedDocument_DecodeToDoc_Call{Call: _e.mock.On("DecodeToDoc", _a0)}
}

func (_c *EncodedDocument_DecodeToDoc_Call) Run(run func(_a0 *core.DocumentMapping)) *EncodedDocument_DecodeToDoc_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*core.DocumentMapping))
	})
	return _c
}

func (_c *EncodedDocument_DecodeToDoc_Call) Return(_a0 core.Doc, _a1 error) *EncodedDocument_DecodeToDoc_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *EncodedDocument_DecodeToDoc_Call) RunAndReturn(run func(*core.DocumentMapping) (core.Doc, error)) *EncodedDocument_DecodeToDoc_Call {
	_c.Call.Return(run)
	return _c
}

// Key provides a mock function with given fields:
func (_m *EncodedDocument) Key() []byte {
	ret := _m.Called()

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// EncodedDocument_Key_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Key'
type EncodedDocument_Key_Call struct {
	*mock.Call
}

// Key is a helper method to define mock.On call
func (_e *EncodedDocument_Expecter) Key() *EncodedDocument_Key_Call {
	return &EncodedDocument_Key_Call{Call: _e.mock.On("Key")}
}

func (_c *EncodedDocument_Key_Call) Run(run func()) *EncodedDocument_Key_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *EncodedDocument_Key_Call) Return(_a0 []byte) *EncodedDocument_Key_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *EncodedDocument_Key_Call) RunAndReturn(run func() []byte) *EncodedDocument_Key_Call {
	_c.Call.Return(run)
	return _c
}

// Reset provides a mock function with given fields: newKey
func (_m *EncodedDocument) Reset(newKey []byte) {
	_m.Called(newKey)
}

// EncodedDocument_Reset_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Reset'
type EncodedDocument_Reset_Call struct {
	*mock.Call
}

// Reset is a helper method to define mock.On call
//   - newKey []byte
func (_e *EncodedDocument_Expecter) Reset(newKey interface{}) *EncodedDocument_Reset_Call {
	return &EncodedDocument_Reset_Call{Call: _e.mock.On("Reset", newKey)}
}

func (_c *EncodedDocument_Reset_Call) Run(run func(newKey []byte)) *EncodedDocument_Reset_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *EncodedDocument_Reset_Call) Return() *EncodedDocument_Reset_Call {
	_c.Call.Return()
	return _c
}

func (_c *EncodedDocument_Reset_Call) RunAndReturn(run func([]byte)) *EncodedDocument_Reset_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewEncodedDocument interface {
	mock.TestingT
	Cleanup(func())
}

// NewEncodedDocument creates a new instance of EncodedDocument. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewEncodedDocument(t mockConstructorTestingTNewEncodedDocument) *EncodedDocument {
	mock := &EncodedDocument{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
