// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"log/slog"
	"net/http"

	"golang.org/x/exp/jsonrpc2"

	"github.com/stacklok/toolhive/pkg/authz/authorizers"
	mcpparser "github.com/stacklok/toolhive/pkg/mcp"
)

// newListResponseFilter builds the filter for one protected list request. The
// request context is detached from cancellation: the filter can run after the
// request has returned, and its authorization decisions still need the
// caller's identity.
func newListResponseFilter(
	r *http.Request, a authorizers.Authorizer, method string,
	annotationCache *AnnotationCache, passThroughTools map[string]struct{},
) mcpparser.ListResponseFilter {
	detached := r.WithContext(context.WithoutCancel(r.Context()))
	return func(response *jsonrpc2.Response) *jsonrpc2.Response {
		rfw := NewResponseFilteringWriter(nil, a, detached, method, annotationCache, passThroughTools)
		filtered, err := rfw.filterListResponse(response)
		if err != nil {
			slog.Error("error filtering response", "method", method, "error", err)
			return &jsonrpc2.Response{
				ID:    response.ID,
				Error: jsonrpc2.NewError(mcpparser.CodeInternalError, "internal error"),
			}
		}
		return filtered
	}
}
