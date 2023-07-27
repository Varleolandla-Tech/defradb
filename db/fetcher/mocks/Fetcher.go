// Code generated by mockery v2.32.0. DO NOT EDIT.

package mocks

import (
	context "context"

	client "github.com/sourcenetwork/defradb/client"

	core "github.com/sourcenetwork/defradb/core"

	datastore "github.com/sourcenetwork/defradb/datastore"

	fetcher "github.com/sourcenetwork/defradb/db/fetcher"

	mapper "github.com/sourcenetwork/defradb/planner/mapper"

	mock "github.com/stretchr/testify/mock"
)

// Fetcher is an autogenerated mock type for the Fetcher type
type Fetcher struct {
	mock.Mock
}

type Fetcher_Expecter struct {
	mock *mock.Mock
}

func (_m *Fetcher) EXPECT() *Fetcher_Expecter {
	return &Fetcher_Expecter{mock: &_m.Mock}
}

// Close provides a mock function with given fields:
func (_m *Fetcher) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Fetcher_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type Fetcher_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *Fetcher_Expecter) Close() *Fetcher_Close_Call {
	return &Fetcher_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *Fetcher_Close_Call) Run(run func()) *Fetcher_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Fetcher_Close_Call) Return(_a0 error) *Fetcher_Close_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Fetcher_Close_Call) RunAndReturn(run func() error) *Fetcher_Close_Call {
	_c.Call.Return(run)
	return _c
}

// FetchNext provides a mock function with given fields: ctx
func (_m *Fetcher) FetchNext(ctx context.Context) (fetcher.EncodedDocument, fetcher.ExecInfo, error) {
	ret := _m.Called(ctx)

	var r0 fetcher.EncodedDocument
	var r1 fetcher.ExecInfo
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context) (fetcher.EncodedDocument, fetcher.ExecInfo, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) fetcher.EncodedDocument); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fetcher.EncodedDocument)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) fetcher.ExecInfo); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Get(1).(fetcher.ExecInfo)
	}

	if rf, ok := ret.Get(2).(func(context.Context) error); ok {
		r2 = rf(ctx)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Fetcher_FetchNext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FetchNext'
type Fetcher_FetchNext_Call struct {
	*mock.Call
}

// FetchNext is a helper method to define mock.On call
//   - ctx context.Context
func (_e *Fetcher_Expecter) FetchNext(ctx interface{}) *Fetcher_FetchNext_Call {
	return &Fetcher_FetchNext_Call{Call: _e.mock.On("FetchNext", ctx)}
}

func (_c *Fetcher_FetchNext_Call) Run(run func(ctx context.Context)) *Fetcher_FetchNext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *Fetcher_FetchNext_Call) Return(_a0 fetcher.EncodedDocument, _a1 fetcher.ExecInfo, _a2 error) *Fetcher_FetchNext_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *Fetcher_FetchNext_Call) RunAndReturn(run func(context.Context) (fetcher.EncodedDocument, fetcher.ExecInfo, error)) *Fetcher_FetchNext_Call {
	_c.Call.Return(run)
	return _c
}

// FetchNextDecoded provides a mock function with given fields: ctx
func (_m *Fetcher) FetchNextDecoded(ctx context.Context) (*client.Document, fetcher.ExecInfo, error) {
	ret := _m.Called(ctx)

	var r0 *client.Document
	var r1 fetcher.ExecInfo
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context) (*client.Document, fetcher.ExecInfo, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) *client.Document); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Document)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) fetcher.ExecInfo); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Get(1).(fetcher.ExecInfo)
	}

	if rf, ok := ret.Get(2).(func(context.Context) error); ok {
		r2 = rf(ctx)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Fetcher_FetchNextDecoded_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FetchNextDecoded'
type Fetcher_FetchNextDecoded_Call struct {
	*mock.Call
}

// FetchNextDecoded is a helper method to define mock.On call
//   - ctx context.Context
func (_e *Fetcher_Expecter) FetchNextDecoded(ctx interface{}) *Fetcher_FetchNextDecoded_Call {
	return &Fetcher_FetchNextDecoded_Call{Call: _e.mock.On("FetchNextDecoded", ctx)}
}

func (_c *Fetcher_FetchNextDecoded_Call) Run(run func(ctx context.Context)) *Fetcher_FetchNextDecoded_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *Fetcher_FetchNextDecoded_Call) Return(_a0 *client.Document, _a1 fetcher.ExecInfo, _a2 error) *Fetcher_FetchNextDecoded_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *Fetcher_FetchNextDecoded_Call) RunAndReturn(run func(context.Context) (*client.Document, fetcher.ExecInfo, error)) *Fetcher_FetchNextDecoded_Call {
	_c.Call.Return(run)
	return _c
}

// FetchNextDoc provides a mock function with given fields: ctx, mapping
func (_m *Fetcher) FetchNextDoc(ctx context.Context, mapping *core.DocumentMapping) ([]byte, core.Doc, fetcher.ExecInfo, error) {
	ret := _m.Called(ctx, mapping)

	var r0 []byte
	var r1 core.Doc
	var r2 fetcher.ExecInfo
	var r3 error
	if rf, ok := ret.Get(0).(func(context.Context, *core.DocumentMapping) ([]byte, core.Doc, fetcher.ExecInfo, error)); ok {
		return rf(ctx, mapping)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *core.DocumentMapping) []byte); ok {
		r0 = rf(ctx, mapping)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *core.DocumentMapping) core.Doc); ok {
		r1 = rf(ctx, mapping)
	} else {
		r1 = ret.Get(1).(core.Doc)
	}

	if rf, ok := ret.Get(2).(func(context.Context, *core.DocumentMapping) fetcher.ExecInfo); ok {
		r2 = rf(ctx, mapping)
	} else {
		r2 = ret.Get(2).(fetcher.ExecInfo)
	}

	if rf, ok := ret.Get(3).(func(context.Context, *core.DocumentMapping) error); ok {
		r3 = rf(ctx, mapping)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// Fetcher_FetchNextDoc_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FetchNextDoc'
type Fetcher_FetchNextDoc_Call struct {
	*mock.Call
}

// FetchNextDoc is a helper method to define mock.On call
//   - ctx context.Context
//   - mapping *core.DocumentMapping
func (_e *Fetcher_Expecter) FetchNextDoc(ctx interface{}, mapping interface{}) *Fetcher_FetchNextDoc_Call {
	return &Fetcher_FetchNextDoc_Call{Call: _e.mock.On("FetchNextDoc", ctx, mapping)}
}

func (_c *Fetcher_FetchNextDoc_Call) Run(run func(ctx context.Context, mapping *core.DocumentMapping)) *Fetcher_FetchNextDoc_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*core.DocumentMapping))
	})
	return _c
}

func (_c *Fetcher_FetchNextDoc_Call) Return(_a0 []byte, _a1 core.Doc, _a2 fetcher.ExecInfo, _a3 error) *Fetcher_FetchNextDoc_Call {
	_c.Call.Return(_a0, _a1, _a2, _a3)
	return _c
}

func (_c *Fetcher_FetchNextDoc_Call) RunAndReturn(run func(context.Context, *core.DocumentMapping) ([]byte, core.Doc, fetcher.ExecInfo, error)) *Fetcher_FetchNextDoc_Call {
	_c.Call.Return(run)
	return _c
}

// Init provides a mock function with given fields: ctx, txn, col, fields, filter, docmapper, reverse, showDeleted
func (_m *Fetcher) Init(ctx context.Context, txn datastore.Txn, col *client.CollectionDescription, fields []client.FieldDescription, filter *mapper.Filter, docmapper *core.DocumentMapping, reverse bool, showDeleted bool) error {
	ret := _m.Called(ctx, txn, col, fields, filter, docmapper, reverse, showDeleted)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, datastore.Txn, *client.CollectionDescription, []client.FieldDescription, *mapper.Filter, *core.DocumentMapping, bool, bool) error); ok {
		r0 = rf(ctx, txn, col, fields, filter, docmapper, reverse, showDeleted)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Fetcher_Init_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Init'
type Fetcher_Init_Call struct {
	*mock.Call
}

// Init is a helper method to define mock.On call
//   - ctx context.Context
//   - txn datastore.Txn
//   - col *client.CollectionDescription
//   - fields []client.FieldDescription
//   - filter *mapper.Filter
//   - docmapper *core.DocumentMapping
//   - reverse bool
//   - showDeleted bool
func (_e *Fetcher_Expecter) Init(ctx interface{}, txn interface{}, col interface{}, fields interface{}, filter interface{}, docmapper interface{}, reverse interface{}, showDeleted interface{}) *Fetcher_Init_Call {
	return &Fetcher_Init_Call{Call: _e.mock.On("Init", ctx, txn, col, fields, filter, docmapper, reverse, showDeleted)}
}

func (_c *Fetcher_Init_Call) Run(run func(ctx context.Context, txn datastore.Txn, col *client.CollectionDescription, fields []client.FieldDescription, filter *mapper.Filter, docmapper *core.DocumentMapping, reverse bool, showDeleted bool)) *Fetcher_Init_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(datastore.Txn), args[2].(*client.CollectionDescription), args[3].([]client.FieldDescription), args[4].(*mapper.Filter), args[5].(*core.DocumentMapping), args[6].(bool), args[7].(bool))
	})
	return _c
}

func (_c *Fetcher_Init_Call) Return(_a0 error) *Fetcher_Init_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Fetcher_Init_Call) RunAndReturn(run func(context.Context, datastore.Txn, *client.CollectionDescription, []client.FieldDescription, *mapper.Filter, *core.DocumentMapping, bool, bool) error) *Fetcher_Init_Call {
	_c.Call.Return(run)
	return _c
}

// Start provides a mock function with given fields: ctx, spans
func (_m *Fetcher) Start(ctx context.Context, spans core.Spans) error {
	ret := _m.Called(ctx, spans)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, core.Spans) error); ok {
		r0 = rf(ctx, spans)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Fetcher_Start_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Start'
type Fetcher_Start_Call struct {
	*mock.Call
}

// Start is a helper method to define mock.On call
//   - ctx context.Context
//   - spans core.Spans
func (_e *Fetcher_Expecter) Start(ctx interface{}, spans interface{}) *Fetcher_Start_Call {
	return &Fetcher_Start_Call{Call: _e.mock.On("Start", ctx, spans)}
}

func (_c *Fetcher_Start_Call) Run(run func(ctx context.Context, spans core.Spans)) *Fetcher_Start_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(core.Spans))
	})
	return _c
}

func (_c *Fetcher_Start_Call) Return(_a0 error) *Fetcher_Start_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Fetcher_Start_Call) RunAndReturn(run func(context.Context, core.Spans) error) *Fetcher_Start_Call {
	_c.Call.Return(run)
	return _c
}

// NewFetcher creates a new instance of Fetcher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFetcher(t interface {
	mock.TestingT
	Cleanup(func())
}) *Fetcher {
	mock := &Fetcher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
