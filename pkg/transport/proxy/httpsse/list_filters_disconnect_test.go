// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpsse_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/authz"
	"github.com/stacklok/toolhive/pkg/authz/authorizers/cedar"
	"github.com/stacklok/toolhive/pkg/mcp"
	"github.com/stacklok/toolhive/pkg/transport/proxy/httpsse"
	"github.com/stacklok/toolhive/pkg/transport/types"
)

// disconnectClock is a goroutine-safe fake clock that the test moves forward.
type disconnectClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *disconnectClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *disconnectClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// startDisconnectProxy starts a proxy with the same authenticate and Cedar
// tool-list authz middleware as TestSSEToolsListIsFilteredByAuthz, and installs
// clock as its list-filter clock before Start.
func startDisconnectProxy(t *testing.T, clock *disconnectClock) (*httpsse.HTTPSSEProxy, string) {
	t.Helper()

	authenticate := types.NamedMiddleware{Name: "authenticate", Function: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller := &auth.Identity{
				PrincipalInfo: auth.PrincipalInfo{Subject: "owner", Claims: map[string]any{"iss": "issuer", "sub": "owner"}},
				Token:         "owner",
			}
			next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), caller)))
		})
	}}

	authorizer, err := cedar.NewCedarAuthorizer(cedar.ConfigOptions{
		Policies:     []string{`permit(principal, action == Action::"call_tool", resource == Tool::"weather");`},
		EntitiesJSON: `[]`,
	}, "")
	require.NoError(t, err)
	authzMW := types.NamedMiddleware{Name: "authz", Function: func(next http.Handler) http.Handler {
		return mcp.ParsingMiddleware(authz.Middleware(authorizer, next, nil))
	}}

	port := disconnectFreePort(t)
	proxy := httpsse.NewHTTPSSEProxy("127.0.0.1", port, false, nil, []types.NamedMiddleware{authenticate, authzMW})
	httpsse.SetPendingListClockForTest(proxy, clock.Now)
	require.NoError(t, proxy.Start(t.Context()))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxy.Stop(stopCtx)
	})
	return proxy, fmt.Sprintf("http://127.0.0.1:%d", port)
}

// disconnectFreePort asks the OS for an unused TCP port on 127.0.0.1.
func disconnectFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// disconnectStream is an open GET /sse stream. sessionID comes from the endpoint
// event; done is closed when the server ends the stream.
type disconnectStream struct {
	sessionID string
	done      <-chan struct{}
}

// openDisconnectStream opens /sse and reads the session id from the endpoint
// event. The body is closed on test cleanup.
func openDisconnectStream(t *testing.T, base string) disconnectStream {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/sse", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "owner")
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	idCh := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if i := strings.Index(line, "session_id="); i >= 0 && strings.HasPrefix(line, "data:") {
				select {
				case idCh <- line[i+len("session_id="):]:
				default:
				}
			}
		}
	}()

	select {
	case id := <-idCh:
		return disconnectStream{sessionID: id, done: done}
	case <-done:
		t.Fatal("SSE stream ended before the endpoint event")
	case <-time.After(5 * time.Second):
		t.Fatal("no endpoint event on the SSE stream")
	}
	return disconnectStream{}
}

// postDisconnectList sends a tools/list request with the given numeric ID and
// returns the HTTP status. On 202 it drains the forwarded message from the
// backend channel, so the next non-blocking send cannot fail.
func postDisconnectList(t *testing.T, proxy *httpsse.HTTPSSEProxy, base, sessionID string, id int) int {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, id)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		base+"/messages?session_id="+sessionID, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "owner")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		select {
		case <-proxy.GetMessageChannel():
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d was accepted but never forwarded", id)
		}
	}
	return resp.StatusCode
}

// TestSSESessionDisconnectsAfterExpiredListMarkerLimit proves that a session
// whose tools/list requests all time out is disconnected once it would exceed
// maxExpiredListMarkers, and that another session is left connected. Each POST
// advances the clock past the 2 minute pendingListTimeout, so every earlier
// request has expired into a marker before the next one is added.
func TestSSESessionDisconnectsAfterExpiredListMarkerLimit(t *testing.T) {
	t.Parallel()

	clock := &disconnectClock{now: time.Unix(1_700_000_000, 0)}
	proxy, base := startDisconnectProxy(t, clock)

	stream := openDisconnectStream(t, base)
	other := openDisconnectStream(t, base)

	// Requests 1 to maxExpiredListMarkers are accepted. The next one would push
	// the markers to the cap, so it is refused with 429 and the stream closes.
	for id := 1; id <= httpsse.MaxExpiredListMarkersForTest+1; id++ {
		clock.Advance(3 * time.Minute)
		want := http.StatusAccepted
		if id > httpsse.MaxExpiredListMarkersForTest {
			want = http.StatusTooManyRequests
		}
		require.Equal(t, want, postDisconnectList(t, proxy, base, stream.sessionID, id),
			"tools/list request %d", id)
	}

	select {
	case <-stream.done:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE stream was not closed after the expired-marker limit was reached")
	}

	// The other session never reached the limit: its stream is still open and
	// it can still send a request.
	select {
	case <-other.done:
		t.Fatal("a session below the limit was disconnected")
	default:
	}
	require.Equal(t, http.StatusAccepted, postDisconnectList(t, proxy, base, other.sessionID, 1))
}
