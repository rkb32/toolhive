// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpsse_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/jsonrpc2"

	"github.com/stacklok/toolhive/pkg/transport/proxy/httpsse"
)

// openEventsForTest opens GET /sse, reads the session id from the endpoint
// event, and returns the session id with a channel of the events after it.
// The body is closed on test cleanup.
func openEventsForTest(t *testing.T, base string) (string, <-chan sseEvent) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/sse", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "owner")
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	events := readSSEEvents(resp.Body)
	endpoint := receiveEventForTest(t, events)
	require.Equal(t, "endpoint", endpoint.name)
	sessionID := endpoint.data[strings.Index(endpoint.data, "session_id=")+len("session_id="):]
	return sessionID, events
}

// receiveEventForTest waits up to 5 seconds for the next SSE event.
func receiveEventForTest(t *testing.T, events <-chan sseEvent) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-events:
		require.True(t, ok, "SSE stream ended")
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no SSE event arrived")
		return sseEvent{}
	}
}

// postJSONForTest sends body to /messages and returns the HTTP status. It does
// not read the backend channel; the caller does that for accepted requests.
func postJSONForTest(t *testing.T, base, sessionID, body string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		base+"/messages?session_id="+sessionID, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "owner")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestSSEReusedRequestIDIsRefused proves that a request reusing the ID of a
// pending tools/list is refused with 409, whatever its method. Otherwise the
// backend's answer to the new request would be filtered as the list answer.
func TestSSEReusedRequestIDIsRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "tools/call with the list request's id",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather"}}`,
			want: http.StatusConflict,
		},
		{
			name: "tools/list with the same id",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			want: http.StatusConflict,
		},
		{
			name: "tools/call with a fresh id",
			body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"weather"}}`,
			want: http.StatusAccepted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := &disconnectClock{now: time.Unix(1_700_000_000, 0)}
			proxy, base := startDisconnectProxy(t, clock)
			sessionID, _ := openEventsForTest(t, base)

			// The first tools/list stays pending: nothing answers it.
			require.Equal(t, http.StatusAccepted, postDisconnectList(t, proxy, base, sessionID, 1))

			got := postJSONForTest(t, base, sessionID, tt.body)
			assert.Equal(t, tt.want, got)
			if got == http.StatusAccepted {
				select {
				case <-proxy.GetMessageChannel():
				case <-time.After(5 * time.Second):
					t.Fatal("accepted request was never forwarded")
				}
			}
		})
	}
}

// TestSSEListAnswerAfterTimeout proves that a tools/list answer is filtered
// when it arrives within the timeout, and that after the timeout it is replaced
// by an error, so the unfiltered list never reaches the client.
func TestSSEListAnswerAfterTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		advance   time.Duration
		wantError bool
	}{
		{name: "answer within the timeout is filtered", advance: 0, wantError: false},
		{name: "answer after the timeout is an error", advance: 3 * time.Minute, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := &disconnectClock{now: time.Unix(1_700_000_000, 0)}
			proxy, base := startDisconnectProxy(t, clock)
			sessionID, events := openEventsForTest(t, base)

			// Not via postDisconnectList: it drains the backend channel, and the
			// answer below needs the forwarded request from it.
			listBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
			require.Equal(t, http.StatusAccepted, postJSONForTest(t, base, sessionID, listBody))
			clock.Advance(tt.advance)

			// The backend's answer for the request, with the proxy's routed ID.
			answer := sendBackendListAnswerForTest(t, proxy)
			require.NoError(t, proxy.ForwardResponseToClients(t.Context(), answer))

			ev := receiveEventForTest(t, events)
			if tt.wantError {
				assert.Contains(t, ev.data, "list request timed out")
				assert.NotContains(t, ev.data, "weather", "an expired answer must not carry the list")
				return
			}
			assert.Contains(t, ev.data, "weather")
			assert.NotContains(t, ev.data, "secret", "a tool the caller cannot read must not be listed")
		})
	}
}

// sendBackendListAnswerForTest takes the forwarded tools/list request from the
// backend channel and returns a response for it that lists two tools.
func sendBackendListAnswerForTest(t *testing.T, proxy *httpsse.HTTPSSEProxy) *jsonrpc2.Response {
	t.Helper()
	select {
	case msg := <-proxy.GetMessageChannel():
		req, ok := msg.(*jsonrpc2.Request)
		require.True(t, ok, "backend received %T, want a request", msg)
		return &jsonrpc2.Response{
			ID:     req.ID,
			Result: []byte(`{"tools":[{"name":"weather"},{"name":"secret"}]}`),
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tools/list was never forwarded to the backend")
		return nil
	}
}
