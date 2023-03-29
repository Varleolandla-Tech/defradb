// Copyright 2022 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package cli

import "github.com/sourcenetwork/defradb/errors"

const (
	errMissingArg                  string = "missing arguement"
	errMissingArgs                 string = "missing arguements"
	errTooManyArgs                 string = "too many arguments"
	errEmptyStdin                  string = "empty stdin"
	errEmptyFile                   string = "empty file"
	errFailedToReadFile            string = "failed to read file"
	errFailedToReadStdin           string = "failed to read stdin"
	errFailedToCreateRPCClient     string = "failed to create RPC client"
	errFailedToAddReplicator       string = "failed to add replicator, request failed"
	errFailedToJoinEndpoint        string = "failed to join endpoint"
	errFailedToSendRequest         string = "failed to send request"
	errFailedToReadResponseBody    string = "failed to read response body"
	errFailedToStatStdOut          string = "failed to stat stdout"
	errFailedToHandleGQLErrors     string = "failed to handle GraphQL errors"
	errFailedToPrettyPrintResponse string = "failed to pretty print response"
	errFailedToUnmarshalResponse   string = "failed to unmarshal response"
)

// Errors returnable from this package.
//
// This list is incomplete and undefined errors may also be returned.
// Errors returned from this package may be tested against these errors with errors.Is.
var (
	ErrMissingArg                  = errors.New(errMissingArg)
	ErrMissingArgs                 = errors.New(errMissingArgs)
	ErrTooManyArgs                 = errors.New(errTooManyArgs)
	ErrEmptyFile                   = errors.New(errEmptyFile)
	ErrEmptyStdin                  = errors.New(errEmptyStdin)
	ErrFailedToReadFile            = errors.New(errFailedToReadFile)
	ErrFailedToReadStdin           = errors.New(errFailedToReadStdin)
	ErrFailToWrapRPCClient         = errors.New(errFailedToCreateRPCClient)
	ErrFailedToAddReplicator       = errors.New(errFailedToAddReplicator)
	ErrFailedToJoinEndpoint        = errors.New(errFailedToJoinEndpoint)
	ErrFailedToSendRequest         = errors.New(errFailedToSendRequest)
	ErrFailedToReadResponseBody    = errors.New(errFailedToReadResponseBody)
	ErrFailedToStatStdOut          = errors.New(errFailedToStatStdOut)
	ErrFailedToHandleGQLErrors     = errors.New(errFailedToHandleGQLErrors)
	ErrFailedToPrettyPrintResponse = errors.New(errFailedToPrettyPrintResponse)
	ErrFailedToUnmarshalResponse   = errors.New(errFailedToUnmarshalResponse)
)

func NewErrMissingArg(name string) error {
	return errors.New(errMissingArg, errors.NewKV("Name", name))
}

func NewErrMissingArgs(count int, provided int) error {
	return errors.New(errMissingArgs, errors.NewKV("Required", count), errors.NewKV("Provided", provided))
}

func NewFailedToReadFile(inner error) error {
	return errors.Wrap(errFailedToReadFile, inner)
}

func NewFailedToReadStdin(inner error) error {
	return errors.Wrap(errFailedToReadStdin, inner)
}

func NewErrFailedToCreateRPCClient(inner error) error {
	return errors.Wrap(errFailedToCreateRPCClient, inner)
}

func NewErrFailedToAddReplicator(inner error) error {
	return errors.Wrap(errFailedToAddReplicator, inner)
}

func NewErrFailedToJoinEndpoint(inner error) error {
	return errors.Wrap(errFailedToJoinEndpoint, inner)
}

func NewErrFailedToSendRequest(inner error) error {
	return errors.Wrap(errFailedToSendRequest, inner)
}

func NewErrFailedToReadResponseBody(inner error) error {
	return errors.Wrap(errFailedToReadResponseBody, inner)
}

func NewErrFailedToStatStdOut(inner error) error {
	return errors.Wrap(errFailedToStatStdOut, inner)
}

func NewErrFailedToHandleGQLErrors(inner error) error {
	return errors.Wrap(errFailedToHandleGQLErrors, inner)
}

func NewErrFailedToPrettyPrintResponse(inner error) error {
	return errors.Wrap(errFailedToPrettyPrintResponse, inner)
}

func NewErrFailedToUnmarshalResponse(inner error) error {
	return errors.Wrap(errFailedToUnmarshalResponse, inner)
}
