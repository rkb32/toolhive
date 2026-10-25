// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpsse

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/exp/jsonrpc2"

	"github.com/stacklok/toolhive/pkg/mcp"
)

// maxPendingListResponses caps the live list requests one SSE session may have
// outstanding. A live request is one still within pendingListTimeout. When a
// session is at the cap, add refuses further protected list requests until
// time frees a slot or the session reconnects, which drops its entries.
const maxPendingListResponses = 16

// pendingListTimeout is how long a protected list request may wait for its
// backend answer. After it, the request's filter is discarded and only an
// expired marker remains. A late answer is then not sent as the unfiltered
// list: the client receives a JSON-RPC error with its original ID instead.
const pendingListTimeout = 2 * time.Minute

// maxExpiredListMarkers caps the expired markers one session may hold. A
// marker is removed only by a late answer or by dropSession, so without a cap
// a backend that never answers would grow the table without bound. add refuses
// with errExpiredMarkersFull once a session's markers, counting the entries
// that expire during that add, would reach this cap. The caller disconnects the
// session, so the app reconnects with a clean table.
const maxExpiredListMarkers = 64

var (
	// errTooManyPendingLists is returned by add when the session already has
	// maxPendingListResponses live requests. Live slots free up after
	// pendingListTimeout, so the session is not disconnected.
	errTooManyPendingLists = errors.New("too many outstanding list requests")
	// errExpiredMarkersFull is returned by add when the session has reached
	// maxExpiredListMarkers. The caller must disconnect the session.
	errExpiredMarkersFull = errors.New("too many timed-out list requests")
	// errDuplicateListRequest is returned by add when the routed ID is already
	// pending for this session, live or expired.
	errDuplicateListRequest = errors.New("duplicate outstanding list request id")
	// errSessionNotLive is returned by add when the session's SSE connection
	// is not held by this instance.
	errSessionNotLive = errors.New("SSE connection not held by this instance")
)

// pendingListEntry is one outstanding protected list request. A nil filter
// marks an expired request: its answer must not be filtered and sent.
type pendingListEntry struct {
	filter  mcp.ListResponseFilter
	expires time.Time
}

// pendingListState is what take found for a routed ID.
type pendingListState int

const (
	// pendingNone means the routed ID is not an outstanding protected list request.
	pendingNone pendingListState = iota
	// pendingLive means the request is within its timeout; take returns its filter.
	pendingLive
	// pendingExpired means the request timed out; take returns no filter.
	pendingExpired
)

// pendingListFilters holds the response filter for each protected list request
// whose answer has not been delivered yet, keyed by session and then by the
// routed wire ID. An entry is removed when its response is routed, and the whole
// session's entries are dropped when the session disconnects. A request whose
// answer does not arrive within pendingListTimeout becomes an expired marker,
// which is removed the same way. Markers are bounded by maxExpiredListMarkers.
//
// The zero value is ready to use. now is the clock; nil means time.Now.
//
// Lock ordering: mu is the only lock in this structure. add calls its alive
// callback and reads now with mu held, so alive must not call back into
// pendingListFilters. alive reads liveSSESessions, which removeClient updates
// before it calls dropSession. An add that sees the session alive therefore
// completes before dropSession takes mu, and dropSession removes its entry. An
// add that runs after dropSession sees the session gone and refuses.
type pendingListFilters struct {
	mu        sync.Mutex
	bySession map[string]map[string]pendingListEntry
	now       func() time.Time
}

// clock returns the current time. It must be called with mu held.
func (p *pendingListFilters) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

// add records filter for a request routed as routedID, to expire after
// pendingListTimeout. Before the limits are checked, it expires the session's
// timed-out entries. It returns errSessionNotLive when alive reports false,
// errTooManyPendingLists when the session has maxPendingListResponses live
// requests or its markers would reach maxExpiredListMarkers, and
// errDuplicateListRequest when routedID is already recorded. In every error
// case nothing is recorded and the request must not be sent. alive is called
// with mu held.
func (p *pendingListFilters) add(
	sessionID, routedID string, filter mcp.ListResponseFilter, alive func() bool,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !alive() {
		return errSessionNotLive
	}
	if p.bySession == nil {
		p.bySession = make(map[string]map[string]pendingListEntry)
	}
	pending := p.bySession[sessionID]
	if pending == nil {
		pending = make(map[string]pendingListEntry)
		p.bySession[sessionID] = pending
	}

	now := p.clock()
	live, expiring, markers := 0, 0, 0
	for _, e := range pending {
		switch {
		case e.filter == nil:
			markers++
		case now.Before(e.expires):
			live++
		default:
			expiring++
		}
	}
	// Refuse before expiring anything, so a refused add leaves the table as it was.
	if live >= maxPendingListResponses {
		return errTooManyPendingLists
	}
	if markers+expiring >= maxExpiredListMarkers {
		return errExpiredMarkersFull
	}
	// A client may reuse an ID while its first request is still pending. Refuse
	// the second, so the first answer cannot be the only one that gets filtered.
	if _, dup := pending[routedID]; dup {
		return errDuplicateListRequest
	}
	for id, e := range pending {
		if e.filter != nil && !now.Before(e.expires) {
			pending[id] = pendingListEntry{expires: e.expires}
		}
	}
	pending[routedID] = pendingListEntry{filter: filter, expires: now.Add(pendingListTimeout)}
	return nil
}

// take removes the entry recorded for routedID and reports what it was. It
// returns pendingNone and a nil filter when routedID is not an outstanding
// protected list request, including when its session has disconnected. It
// returns pendingLive and the filter when the request is within its timeout,
// and pendingExpired and a nil filter when it timed out, whether or not add
// has already turned it into a marker. The entry is gone after take in every
// case.
func (p *pendingListFilters) take(sessionID, routedID string) (mcp.ListResponseFilter, pendingListState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pending := p.bySession[sessionID]
	e, ok := pending[routedID]
	if !ok {
		return nil, pendingNone
	}
	delete(pending, routedID)
	if len(pending) == 0 {
		delete(p.bySession, sessionID)
	}
	if e.filter == nil || !p.clock().Before(e.expires) {
		return nil, pendingExpired
	}
	return e.filter, pendingLive
}

// has reports whether routedID is recorded for sessionID, live or expired.
func (p *pendingListFilters) has(sessionID, routedID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.bySession[sessionID][routedID]
	return ok
}

// routedRequestID returns the routed wire ID of a request msg, which is the
// key add and take use. It reports false for anything but a request with an ID.
func routedRequestID(msg jsonrpc2.Message) (string, bool) {
	req, ok := msg.(*jsonrpc2.Request)
	if !ok || !req.ID.IsValid() {
		return "", false
	}
	routed, ok := req.ID.Raw().(string)
	return routed, ok
}

// remove drops one entry added by add, used when the request was not sent.
// It does nothing when no entry exists for routedID.
func (p *pendingListFilters) remove(sessionID, routedID string) {
	p.take(sessionID, routedID)
}

// dropSession forgets every outstanding list request and expired marker of
// sessionID.
func (p *pendingListFilters) dropSession(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.bySession, sessionID)
}
