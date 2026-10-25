// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpsse

import "time"

// MaxExpiredListMarkersForTest exposes maxExpiredListMarkers to the external
// httpsse_test package, which cannot import unexported names.
const MaxExpiredListMarkersForTest = maxExpiredListMarkers

// SetPendingListClockForTest replaces the list-filter clock of p. It must be
// called before p.Start, so the clock is not read concurrently with the swap.
func SetPendingListClockForTest(p *HTTPSSEProxy, now func() time.Time) {
	p.pendingListFilters.now = now
}
