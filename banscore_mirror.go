package neutrino

import (
	"sync"

	"github.com/gcash/bchd/connmgr"
)

// banScoreMirror mirrors the ban score a peer keeps for us.  The check that a
// request still fits and the add that counts it happen together, so two
// senders cannot each see room and together pass the score the peer bans at.
type banScoreMirror struct {
	mtx   sync.Mutex
	score connmgr.DynamicBanScore

	// reserved is room held for requests a sender will send later, which
	// no other take may use.
	reserved uint32
}

// Int returns the score as it is now.
func (m *banScoreMirror) Int() uint32 {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.score.Int()
}

// tryTake adds add to the score when the score plus room is at max or below,
// and reports whether it did.  room is at least add: a sender that will send
// a second request after this one passes the scores of both as room, so that
// it only starts what it can finish.
func (m *banScoreMirror) tryTake(add, room, max uint32) bool {
	return m.tryReserve(add, room-add, max)
}

// tryReserve adds add to the score and holds reserve more for a request sent
// later, when the score, what is held already, add and reserve are at max or
// below, and reports whether it did.  The sender then claims what it held,
// or releases it.
func (m *banScoreMirror) tryReserve(add, reserve, max uint32) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.score.Int()+m.reserved+add+reserve > max {
		return false
	}
	m.score.Increase(0, add)
	m.reserved += reserve
	return true
}

// claim counts n of the room held toward the score.
func (m *banScoreMirror) claim(n uint32) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.reserved -= min(n, m.reserved)
	m.score.Increase(0, n)
}

// release gives back n of the room held, unused.
func (m *banScoreMirror) release(n uint32) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.reserved -= min(n, m.reserved)
}

// String returns the score the way DynamicBanScore does, for logs.
func (m *banScoreMirror) String() string {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.score.String()
}
