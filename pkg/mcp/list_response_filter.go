// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"

	"golang.org/x/exp/jsonrpc2"
)

// ListResponseFilter filters one backend response to a protected list method
// (for example tools/list) for the caller whose request set the filter. It
// always returns a response to deliver: the filtered list, or an error response
// if the list cannot be filtered, which fails closed.
type ListResponseFilter func(response *jsonrpc2.Response) *jsonrpc2.Response

type listResponseFilterKey struct{}

// WithListResponseFilter returns a copy of ctx that carries filter. The authz
// middleware sets it on every protected list request, so a transport that
// delivers the backend's answer after the request has returned (the SSE proxy)
// can apply the same filter at delivery time.
func WithListResponseFilter(ctx context.Context, filter ListResponseFilter) context.Context {
	return context.WithValue(ctx, listResponseFilterKey{}, filter)
}

// ListResponseFilterFrom returns the filter carried by ctx, or nil when the
// request is not a protected list request.
func ListResponseFilterFrom(ctx context.Context) ListResponseFilter {
	filter, _ := ctx.Value(listResponseFilterKey{}).(ListResponseFilter)
	return filter
}
