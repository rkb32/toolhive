// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpsse

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/jsonrpc2"

	"github.com/stacklok/toolhive/pkg/mcp"
)

func testListFilter(*jsonrpc2.Response) *jsonrpc2.Response { return nil }

func alwaysAlive() bool { return true }

// testClock returns a clock that stays put until advance moves it forward.
func testClock() (now func() time.Time, advance func(time.Duration)) {
	t := time.Unix(1_700_000_000, 0)
	return func() time.Time { return t }, func(d time.Duration) { t = t.Add(d) }
}

func TestPendingListFiltersRefusesBeyondCap(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	var filter mcp.ListResponseFilter = testListFilter

	for i := range maxPendingListResponses {
		require.NoError(t, p.add("s1", "k"+string(rune('a'+i)), filter, alwaysAlive))
	}
	err := p.add("s1", "overflow", filter, alwaysAlive)
	assert.ErrorIs(t, err, errTooManyPendingLists)
	_, state := p.take("s1", "overflow")
	assert.Equal(t, pendingNone, state, "a refused request must leave no entry")
}

func TestPendingListFiltersDropSessionIsolatesSessions(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	var filter mcp.ListResponseFilter = testListFilter

	require.NoError(t, p.add("victim", "a", filter, alwaysAlive))
	require.NoError(t, p.add("victim", "b", filter, alwaysAlive))
	require.NoError(t, p.add("other", "c", filter, alwaysAlive))

	p.dropSession("victim")

	_, state := p.take("victim", "a")
	assert.Equal(t, pendingNone, state)
	_, state = p.take("victim", "b")
	assert.Equal(t, pendingNone, state)
	_, state = p.take("other", "c")
	assert.Equal(t, pendingLive, state, "dropping one session must not affect another")
}

func TestPendingListFiltersAddRefusesDeadSession(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	var filter mcp.ListResponseFilter = testListFilter

	err := p.add("s1", "k", filter, func() bool { return false })
	assert.ErrorIs(t, err, errSessionNotLive)
	_, state := p.take("s1", "k")
	assert.Equal(t, pendingNone, state, "a dead session must not gain an entry")
}

func TestPendingListFiltersTakeUnknownAndFound(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	marker := errors.New("marker")
	var filter mcp.ListResponseFilter = func(*jsonrpc2.Response) *jsonrpc2.Response {
		return &jsonrpc2.Response{Error: jsonrpc2.NewError(1, marker.Error())}
	}

	_, state := p.take("s1", "unknown")
	assert.Equal(t, pendingNone, state, "an unknown routed ID is not a list request")

	require.NoError(t, p.add("s1", "k", filter, alwaysAlive))
	got, state := p.take("s1", "k")
	require.Equal(t, pendingLive, state, "a recorded request within its timeout is live")
	require.NotNil(t, got, "a live request returns its filter")
	_, state = p.take("s1", "k")
	assert.Equal(t, pendingNone, state, "take removes the entry")
}

func TestPendingListFiltersRemoveUndoesAdd(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	var filter mcp.ListResponseFilter = testListFilter

	require.NoError(t, p.add("s1", "k", filter, alwaysAlive))
	p.remove("s1", "k")
	_, state := p.take("s1", "k")
	assert.Equal(t, pendingNone, state)
}

func TestPendingListFiltersRefusesDuplicateID(t *testing.T) {
	t.Parallel()
	var p pendingListFilters
	var filter mcp.ListResponseFilter = testListFilter

	require.NoError(t, p.add("s1", "k", filter, alwaysAlive))
	err := p.add("s1", "k", filter, alwaysAlive)
	assert.ErrorIs(t, err, errDuplicateListRequest)
	_, state := p.take("s1", "k")
	assert.Equal(t, pendingLive, state, "the first request must keep its filter")
}

func TestPendingListFiltersTimeoutFreesSlots(t *testing.T) {
	t.Parallel()
	now, advance := testClock()
	p := pendingListFilters{now: now}
	var filter mcp.ListResponseFilter = testListFilter

	for i := range maxPendingListResponses {
		require.NoError(t, p.add("s1", "k"+string(rune('a'+i)), filter, alwaysAlive))
	}
	require.ErrorIs(t, p.add("s1", "overflow", filter, alwaysAlive), errTooManyPendingLists)

	advance(pendingListTimeout)
	require.NoError(t, p.add("s1", "overflow", filter, alwaysAlive), "expired requests must free their slots")
}

func TestPendingListFiltersTakeExpiredReportsOnce(t *testing.T) {
	t.Parallel()
	now, advance := testClock()
	p := pendingListFilters{now: now}
	var filter mcp.ListResponseFilter = testListFilter

	require.NoError(t, p.add("s1", "k", filter, alwaysAlive))
	advance(pendingListTimeout)

	got, state := p.take("s1", "k")
	assert.Equal(t, pendingExpired, state, "a timed-out request reports expired")
	assert.Nil(t, got, "an expired request returns no filter")
	_, state = p.take("s1", "k")
	assert.Equal(t, pendingNone, state, "the expired marker is removed by the first take")
}

func TestPendingListFiltersExpiredMarkerCap(t *testing.T) {
	t.Parallel()
	now, _ := testClock()
	p := pendingListFilters{now: now}
	markers := make(map[string]pendingListEntry, maxExpiredListMarkers)
	for i := range maxExpiredListMarkers {
		markers["m"+string(rune('a'+i%26))+string(rune('a'+i/26))] = pendingListEntry{expires: now()}
	}
	p.bySession = map[string]map[string]pendingListEntry{"s1": markers}

	err := p.add("s1", "next", testListFilter, alwaysAlive)
	assert.ErrorIs(t, err, errExpiredMarkersFull, "a session at the marker cap must refuse new list requests")
	_, state := p.take("s1", "next")
	assert.Equal(t, pendingNone, state, "a refused request must leave no entry")
}

func TestPendingListFiltersDropSessionClearsMarkers(t *testing.T) {
	t.Parallel()
	now, advance := testClock()
	p := pendingListFilters{now: now}
	var filter mcp.ListResponseFilter = testListFilter

	require.NoError(t, p.add("s1", "a", filter, alwaysAlive))
	advance(pendingListTimeout)
	require.NoError(t, p.add("s1", "b", filter, alwaysAlive)) // expires "a" into a marker

	p.dropSession("s1")

	assert.NotContains(t, p.bySession, "s1", "dropSession must remove markers as well as live entries")
	_, state := p.take("s1", "a")
	assert.Equal(t, pendingNone, state)
}
