package neutrino

import (
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs"
	"github.com/gcash/bchutil/gcs/builder"
)

// A node gathers the transactions it admits to its mempool into intervals of
// a few seconds and builds one script filter for each, keyed by the hash of
// those transactions.  A service that syncs script filters hears of
// unconfirmed transactions from one feed peer.  Only the feed is asked to
// send the filters, and a filter or a batch of transactions from any other
// peer is ignored.  When the feed disconnects, what it sent is dropped and
// another peer is asked, so two connections never share one record.
//
// An interval with fewer transactions than the floor is always downloaded,
// and its filter is not read.  A wallet on regular filters downloads every
// transaction a peer announces, so for these intervals the requests a peer
// sees are the same whatever the wallet watches.  An interval with that many
// transactions or more is downloaded only when its filter matches a watched
// script, which tells the peer that one of at least that many transactions
// is of interest and nothing more.  Asking only for the interval that
// matched, at the moment it matched, would tell the peer which interval it
// was however the request was padded, which is why a short interval is taken
// whole instead of being hidden inside a run.
//
// An interval to download is pending until the ban score has room for a
// getmptxs.  One request asks for the oldest pending sequence and every
// pending sequence that follows it with no gap.  Those become asked.  An
// asked interval whose transactions have not arrived is pending again after
// mpTxsWait, plus the time its run's transactions take over a slow link,
// counted from the request or from the last transactions the feed sent,
// whichever is later, so a large run still arriving is not asked for twice:
// the node always sends the first interval of a run and may stop once it has
// sent 32MB, so a missing tail is reached by asking again, when it is first.
// An interval asked mpTxsTries times without an answer, or that the feed's
// newer intervals have pushed out of the hour a node keeps, is given up.
// Pending intervals are requested again on each later filter and once a
// second, so a match is fetched once the score has decayed even when no
// later interval arrives.
//
// An answer is accepted when it was asked for, it has the announced number
// of transactions, each full transaction has the ID it is listed with, and
// the double SHA-256 of their IDs is the announced interval hash.  It is
// then done, and a later answer is ignored.  The full transactions are
// delivered without the lock held.  An announcement of a sequence again with
// the same hash and count keeps the interval's state.  A different hash or
// count, or an answer that does not match, means the peer is misbehaving.
// So does, though less surely, an interval fetched because its filter
// matched whose transactions hold nothing we watch: a feed can make up such
// an interval to learn whether we watch a script.  At most mpIntervalsKept
// intervals are remembered, which is as many as a node keeps; the oldest is
// dropped whatever its state.
//
// No service bit or protocol version tells which nodes send these filters.
// A feed has to prove it does by sending one, and until it has, peers keep
// announcing transactions as they do on regular filters.  A feed that sends
// none while transactions are announced to us is replaced by another peer,
// and is not taken again while one that wasn't tried is left.  A feed that
// proved it serves intervals is still replaced from time to time, so that no
// one peer sees for long which large intervals we download.

const (
	// DefaultMempoolFetchFloor is the floor used when none is configured.
	// An interval with fewer transactions than the floor is downloaded whole.
	DefaultMempoolFetchFloor = 200

	// mpIntervalsKept is an hour of intervals, which is what a node keeps.
	mpIntervalsKept = 720

	// mpTxsBanScore is what bchd adds to a peer's ban score for a getmptxs.
	mpTxsBanScore = 2

	// mpTxsWait is how long an asked interval stays asked before it is asked
	// again, besides the time its run takes to arrive.  The node stops a
	// run once the transactions it has sent pass 32MB, so the tail can be
	// missing, and a message can be lost.
	mpTxsWait = 30 * time.Second

	// mpTxBytes and mpSlowLinkRate size how long a run takes to arrive: a
	// transaction of a few hundred bytes, over a link of 16 KiB a second,
	// as Tor and I2P can be.
	mpTxBytes      = 400
	mpSlowLinkRate = 16 * 1024

	// mpTxsTries is how many times an interval is asked for before it is
	// given up.
	mpTxsTries = 3

	// mpNoMatchBanScore is added to the persistent ban score of a feed for
	// an interval fetched on a match whose transactions hold nothing we
	// watch.  An honest feed sends one now and then, as a filter matches
	// by chance and a transaction can be mined before we ask for it.  A
	// feed that makes them up to probe what we watch is banned after ten.
	mpNoMatchBanScore = 10

	// mpFeedProveWait is how long a feed that hasn't sent a filter yet
	// has, from the first transaction announced to us, before another
	// peer is taken: six of the node's intervals.
	mpFeedProveWait = 30 * time.Second

	// mpFeedRotate is about how long a feed that sends filters is kept
	// before another peer is taken, give or take a third.
	mpFeedRotate = 15 * time.Minute

	// mpIntervalTick is how often pending intervals are asked for again when
	// no new filter arrives to ask on.
	mpIntervalTick = time.Second

	// noFeed is the peer id that means there is no feed.  A peer id is taken
	// from a counter that starts at zero and is increased by one when the
	// peer's version message arrives, so the first peer is 1 and no peer is
	// ever 0.
	noFeed = 0
)

// errMpTxs is returned when a peer announces a sequence again with a different
// hash or count, or sends transactions that are not the ones it announced.
var errMpTxs = errors.New("mptxs does not match the interval the peer announced")

// errMpTxsNoMatch is returned for an interval fetched because its filter
// matched what we watch, whose transactions hold nothing of it.
var errMpTxsNoMatch = errors.New("mptxs of an interval whose filter matched " +
	"holds nothing we watch")

// intervalState is whether an announced interval is still to be downloaded,
// has been asked for, or will not be asked for.
type intervalState uint8

const (
	// intervalPending is waiting for a getmptxs.
	intervalPending intervalState = iota

	// intervalAsked was included in a getmptxs at askedAt.
	intervalAsked

	// intervalDone was delivered, or was not downloaded because it is at
	// the floor and its filter did not match.  A later mptxs for it is
	// ignored.
	intervalDone
)

// mpInterval is one interval of mempool transactions the feed has announced.
type mpInterval struct {
	hash    chainhash.Hash
	txCount uint32
	state   intervalState
	askedAt time.Time

	// wait is how long the interval stays asked, and tries how many times
	// it was asked for.
	wait  time.Duration
	tries int

	// matched is whether it is downloaded because its filter matched.
	matched bool
}

// mempoolIntervals is the feed's intervals.  It decides which to download,
// asks for pending runs, and checks the transactions that come back.
type mempoolIntervals struct {
	mtx sync.Mutex

	floor   uint32
	entries func() [][]byte
	deliver func(tx *bchutil.Tx)
	now     func() time.Time

	// ours reports whether a transaction holds something we watch.  When
	// it is nil, every transaction does.
	ours func(tx *bchutil.Tx) bool

	// feedID is the feed peer, or noFeed.  intervals are the ones it has
	// announced that we still keep, and order is their sequence numbers as
	// they arrived, so the oldest can be dropped.  newest is the highest
	// sequence the feed announced, and lastTxs when it last sent the
	// transactions of an interval we asked for.
	feedID    int32
	intervals map[uint32]*mpInterval
	order     []uint32
	newest    uint32
	lastTxs   time.Time

	// proven is whether the feed has sent a filter, which shows that it
	// serves them.  rotateAt is when a proven feed is replaced, and
	// announced when a transaction was first announced to us while the
	// feed hadn't proved itself, or zero.
	proven    bool
	rotateAt  time.Time
	announced time.Time

	// silent holds the peers that were feeds and sent no filter while
	// transactions were announced to us.
	silent map[int32]struct{}
}

// newMempoolIntervals returns an interval watcher.  floor is how many
// transactions an interval must hold before its filter is consulted; zero
// means DefaultMempoolFetchFloor.  entries returns the script keys to match
// a large interval's filter against, deliver takes each full transaction of
// an interval we asked for, and now is the clock asks are timed by.
func newMempoolIntervals(floor uint32, entries func() [][]byte,
	deliver func(tx *bchutil.Tx), now func() time.Time) *mempoolIntervals {

	if floor == 0 {
		floor = DefaultMempoolFetchFloor
	}
	return &mempoolIntervals{
		floor:     floor,
		entries:   entries,
		deliver:   deliver,
		now:       now,
		intervals: make(map[uint32]*mpInterval),
		silent:    make(map[int32]struct{}),
	}
}

// setFeed drops every interval recorded so far and takes id as the feed, which
// has yet to prove that it serves filters.  An id of 0 or less means there is
// no feed, because a connected peer's id is never 0.
func (m *mempoolIntervals) setFeed(id int32) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.takeFeed(id)
}

// takeFeed is setFeed with the lock held.
func (m *mempoolIntervals) takeFeed(id int32) {
	if id <= 0 {
		id = noFeed
	}
	m.feedID = id
	m.intervals = make(map[uint32]*mpInterval)
	m.order = nil
	m.newest = 0
	m.proven = false
	m.announced = time.Time{}

	// A third of mpFeedRotate either way, so that the time a feed is kept
	// can't be told in advance.
	third := int64(mpFeedRotate / 3)
	m.rotateAt = m.now().Add(mpFeedRotate - time.Duration(third) +
		time.Duration(rand.Int64N(2*third)))
}

// offer takes a new peer as the feed when there is none and the peer hasn't
// been a feed that sent no filters, and reports whether it did.
func (m *mempoolIntervals) offer(id int32) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.feedID != noFeed || id <= 0 {
		return false
	}
	if _, ok := m.silent[id]; ok {
		return false
	}
	m.takeFeed(id)
	return true
}

// relayOff returns whether peers needn't announce transactions to us: the feed
// has shown that it sends the filters of intervals.
func (m *mempoolIntervals) relayOff() bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.feedID != noFeed && m.proven
}

// announcedTx notes that a peer announced a transaction to us, which shows that
// a feed that serves filters would have sent some.
func (m *mempoolIntervals) announcedTx() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.feedID != noFeed && !m.proven && m.announced.IsZero() {
		m.announced = m.now()
	}
}

// rotateDue returns whether rotate would replace the feed now: one that sent
// no filter for mpFeedProveWait after a transaction was announced to us, a
// proven one that was kept its time, or none when there is none.
func (m *mempoolIntervals) rotateDue() bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.rotateDueLocked()
}

// rotateDueLocked is rotateDue with the lock held.
func (m *mempoolIntervals) rotateDueLocked() bool {
	now := m.now()
	switch {
	case m.feedID == noFeed:
		return true
	case !m.proven:
		return !m.announced.IsZero() && !now.Before(m.announced.Add(mpFeedProveWait))
	default:
		return !now.Before(m.rotateAt)
	}
}

// rotate replaces the feed when rotateDue says so, with one of the connected
// peers given, and returns the new feed, or noFeed and false when it is kept.
// A feed that sent no filter is not taken again while a peer that hasn't been
// tried is left, and with none left there is no feed, so peers keep
// announcing transactions.  A proven feed is replaced only by another peer.
func (m *mempoolIntervals) rotate(connected []int32) (int32, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if !m.rotateDueLocked() {
		return noFeed, false
	}
	old, proven := m.feedID, m.proven
	if old != noFeed && !proven {
		m.silent[old] = struct{}{}
	}
	candidates := m.candidates(old, connected)
	switch {
	case len(candidates) > 0:
		m.takeFeed(candidates[rand.IntN(len(candidates))])
		return m.feedID, true

	case old != noFeed && proven:
		// The only peer that serves stays the feed until its next
		// turn, with what it announced.
		third := int64(mpFeedRotate / 3)
		m.rotateAt = m.now().Add(mpFeedRotate - time.Duration(third) +
			time.Duration(rand.Int64N(2*third)))
		return noFeed, false

	case old == noFeed:
		return noFeed, false

	default:
		m.takeFeed(noFeed)
		return noFeed, true
	}
}

// candidates returns the connected peers that can become the feed in place of
// old: those that weren't silent feeds.
func (m *mempoolIntervals) candidates(old int32, connected []int32) []int32 {
	var candidates []int32
	for _, id := range connected {
		if _, ok := m.silent[id]; !ok && id != old && id > 0 {
			candidates = append(candidates, id)
		}
	}
	return candidates
}

// feedGone replaces a feed that disconnected with one of the connected peers
// given, other than the ones that were silent feeds, and returns the new
// feed, or noFeed, and whether gone was the feed.
func (m *mempoolIntervals) feedGone(gone int32, connected []int32) (int32, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	delete(m.silent, gone)
	if m.feedID == noFeed || m.feedID != gone {
		return noFeed, false
	}
	next := int32(noFeed)
	if candidates := m.candidates(gone, connected); len(candidates) > 0 {
		next = candidates[rand.IntN(len(candidates))]
	}
	m.takeFeed(next)
	return m.feedID, true
}

// feed returns the feed peer's id.
func (m *mempoolIntervals) feed() (int32, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.feedID == noFeed {
		return 0, false
	}
	return m.feedID, true
}

// onFilter records the interval msg announces from the feed and marks it
// pending when it is to be downloaded.  The same announcement again keeps
// the interval's state.  A different hash or count returns errMpTxs.  A peer
// that is not the feed, and a filter that is not a script filter, are ignored.
func (m *mempoolIntervals) onFilter(peer int32, msg *wire.MsgMpFilter) error {
	if msg.FilterType != wire.GCSFilterScripts {
		return nil
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.feedID == noFeed || peer != m.feedID {
		return nil
	}
	if iv := m.intervals[msg.Seq]; iv != nil {
		if iv.hash != msg.IntervalHash || iv.txCount != msg.TxCount {
			return errMpTxs
		}
		return nil
	}

	// A filter shows that the feed serves them.
	m.proven = true
	m.announced = time.Time{}

	iv := &mpInterval{
		hash:    msg.IntervalHash,
		txCount: msg.TxCount,
		state:   intervalDone,
	}
	if m.fetch(msg) {
		iv.state = intervalPending
		iv.matched = msg.TxCount >= m.floor
	}
	m.remember(msg.Seq, iv)
	if msg.Seq > m.newest {
		m.newest = msg.Seq
	}
	return nil
}

// fetch reports whether the interval is downloaded.  One below the floor
// always is, and its filter is not read, so the request does not depend on
// what we watch.  One at the floor or above is downloaded only when the
// filter matches a script we watch.  A filter that cannot be read matches
// nothing.
func (m *mempoolIntervals) fetch(msg *wire.MsgMpFilter) bool {
	if msg.TxCount < m.floor {
		return true
	}

	// entries only reads the requester, which never calls back here, so
	// holding this lock across it cannot deadlock.
	entries := m.entries()
	if len(entries) == 0 {
		return false
	}
	filter, err := gcs.FromNBytes(builder.DefaultP, builder.DefaultM, msg.Data)
	if err != nil || filter.N() == 0 {
		return false
	}
	matched, err := filter.MatchAny(builder.DeriveKey(&msg.IntervalHash), entries)
	return err == nil && matched
}

// remember stores iv and drops the oldest interval past mpIntervalsKept,
// whatever state it is in.  A node keeps no more than that either.
func (m *mempoolIntervals) remember(seq uint32, iv *mpInterval) {
	m.intervals[seq] = iv
	m.order = append(m.order, seq)
	for len(m.order) > mpIntervalsKept {
		delete(m.intervals, m.order[0])
		m.order = m.order[1:]
	}
}

// next returns a getmptxs for the oldest run of pending intervals, after
// turning asks older than mpTxsWait back into pending.  take is called once,
// and only when there is a run; a false take leaves the run pending and
// returns nil.  There is no feed, or nothing is pending, when it returns nil
// without calling take.
func (m *mempoolIntervals) next(take func() bool) *wire.MsgGetMpTxs {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.feedID == noFeed {
		return nil
	}

	now := m.now()
	for seq, iv := range m.intervals {
		if iv.state == intervalDone {
			continue
		}

		// A node keeps an hour of intervals, and doesn't answer for
		// one it no longer keeps.
		if uint64(seq)+mpIntervalsKept <= uint64(m.newest) {
			log.Debugf("Giving up mempool interval %d, which the feed "+
				"no longer keeps", seq)
			iv.state = intervalDone
			continue
		}
		if iv.state != intervalAsked {
			continue
		}
		since := iv.askedAt
		if m.lastTxs.After(since) {
			since = m.lastTxs
		}
		if now.Before(since.Add(iv.wait)) {
			continue
		}
		if iv.tries >= mpTxsTries {
			log.Debugf("Giving up mempool interval %d after %d "+
				"requests", seq, iv.tries)
			iv.state = intervalDone
			continue
		}
		iv.state = intervalPending
	}
	first, ok := m.oldestPending()
	if !ok {
		return nil
	}
	last := m.runEnd(first)
	if !take() {
		return nil
	}
	var runTxs uint64
	for seq := first; ; seq++ {
		runTxs += uint64(m.intervals[seq].txCount)
		if seq == last {
			break
		}
	}
	wait := mpTxsWaitFor(runTxs)
	for seq := first; ; seq++ {
		iv := m.intervals[seq]
		iv.state = intervalAsked
		iv.askedAt = now
		iv.wait = wait
		iv.tries++
		if seq == last {
			break
		}
	}
	return wire.NewMsgGetMpTxs(wire.GCSFilterScripts, first, last)
}

// mpTxsWaitFor returns how long a run of intervals with txs transactions in
// all stays asked: mpTxsWait, and the time they take over a slow link.
func mpTxsWaitFor(txs uint64) time.Duration {
	return mpTxsWait + time.Duration(txs*mpTxBytes*uint64(time.Second)/mpSlowLinkRate)
}

// oldestPending returns the smallest sequence number that is pending.
func (m *mempoolIntervals) oldestPending() (uint32, bool) {
	var first uint32
	found := false
	for seq, iv := range m.intervals {
		if iv.state != intervalPending {
			continue
		}
		if !found || seq < first {
			first = seq
			found = true
		}
	}
	return first, found
}

// runEnd returns the last sequence of the pending run that starts at first.
// The run stops at a gap or at an interval that is not pending, and it does
// not step past the largest sequence number.
func (m *mempoolIntervals) runEnd(first uint32) uint32 {
	last := first
	for last < ^uint32(0) {
		next := m.intervals[last+1]
		if next == nil || next.state != intervalPending {
			break
		}
		last++
	}
	return last
}

// onTxs checks the transactions peer sent for one interval against the
// interval the feed announced.  An interval that is not asked is ignored,
// including one that is already done.  A count or interval hash that differs,
// or a full transaction with another ID than it is listed with, returns
// errMpTxs and leaves the interval asked, so a later correct answer can still
// be delivered.  The full transactions of an accepted answer are handed to
// deliver without the lock held, and an entry that is only an id is skipped.
// It returns errMpTxsNoMatch, after delivering them, when the interval was
// fetched because its filter matched and none of them holds something we
// watch.
func (m *mempoolIntervals) onTxs(peer int32, msg *wire.MsgMpTxs) error {
	m.mtx.Lock()

	var iv *mpInterval
	if m.feedID != noFeed && peer == m.feedID {
		iv = m.intervals[msg.Seq]
	}
	if iv == nil || iv.state != intervalAsked {
		m.mtx.Unlock()
		return nil
	}
	ids := make([]chainhash.Hash, len(msg.Txs))
	for i := range msg.Txs {
		ids[i] = msg.Txs[i].TxID
		if tx := msg.Txs[i].Tx; tx != nil && tx.TxHash() != ids[i] {
			m.mtx.Unlock()
			return errMpTxs
		}
	}
	if uint32(len(msg.Txs)) != iv.txCount || wire.MpIntervalHash(ids) != iv.hash {
		m.mtx.Unlock()
		return errMpTxs
	}
	iv.state = intervalDone
	m.lastTxs = m.now()
	matched, ours := iv.matched, m.ours
	var txs []*bchutil.Tx
	for i := range msg.Txs {
		if msg.Txs[i].Tx != nil {
			txs = append(txs, bchutil.NewTx(msg.Txs[i].Tx))
		}
	}
	m.mtx.Unlock()

	// What we watch is looked for before the transactions are delivered,
	// which makes them known.
	holdsOurs := !matched || ours == nil
	for _, tx := range txs {
		if holdsOurs {
			break
		}
		holdsOurs = ours(tx)
	}
	for _, tx := range txs {
		m.deliver(tx)
	}
	if !holdsOurs {
		return errMpTxsNoMatch
	}
	return nil
}
