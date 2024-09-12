// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: Storage)
//
// Generated by this command:
//
//	mockgen -package internal -destination internal/storage.go github.com/ory/fosite Storage
//
// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"
	time "time"

	fosite "github.com/ory/fosite"
	gomock "go.uber.org/mock/gomock"
)

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// ClientAssertionJWTValid mocks base method.
func (m *MockStorage) ClientAssertionJWTValid(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientAssertionJWTValid", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ClientAssertionJWTValid indicates an expected call of ClientAssertionJWTValid.
func (mr *MockStorageMockRecorder) ClientAssertionJWTValid(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientAssertionJWTValid", reflect.TypeOf((*MockStorage)(nil).ClientAssertionJWTValid), arg0, arg1)
}

// GetClient mocks base method.
func (m *MockStorage) GetClient(arg0 context.Context, arg1 string) (fosite.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClient", arg0, arg1)
	ret0, _ := ret[0].(fosite.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClient indicates an expected call of GetClient.
func (mr *MockStorageMockRecorder) GetClient(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClient", reflect.TypeOf((*MockStorage)(nil).GetClient), arg0, arg1)
}

// SetClientAssertionJWT mocks base method.
func (m *MockStorage) SetClientAssertionJWT(arg0 context.Context, arg1 string, arg2 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetClientAssertionJWT", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetClientAssertionJWT indicates an expected call of SetClientAssertionJWT.
func (mr *MockStorageMockRecorder) SetClientAssertionJWT(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetClientAssertionJWT", reflect.TypeOf((*MockStorage)(nil).SetClientAssertionJWT), arg0, arg1, arg2)
}
