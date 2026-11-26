package neutrino

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/gcash/bchd/peer"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/neutrino/banman"
)

// feedClock is a clock the feed tests move by hand.
type feedClock struct{ now time.Time }

func (c *feedClock) get() time.Time { return c.now }

// TestMempoolFeedProves checks that a feed has to send a filter before peers
// stop announcing transactions, and that a new feed has to again.
func TestMempoolFeedProves(t *testing.T) {
	clock := &feedClock{now: intervalClock()}
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) {}, clock.get)
	if !m.offer(1) || m.offer(2) {
		t.Fatal("the first peer isn't the feed, or a second one is")
	}
	if m.relayOff() {
		t.Fatal("announcements are off before the feed sent a filter")
	}
	msg, _ := intervalOf(t, 1, 1, []byte{0x53, 0x01}, 1)
	mustOnFilter(t, m, 2, msg)
	if m.relayOff() {
		t.Fatal("a filter from a peer that isn't the feed proved the feed")
	}
	mustOnFilter(t, m, 1, msg)
	if !m.relayOff() {
		t.Fatal("announcements are still on after the feed sent a filter")
	}
	if next, gone := m.feedGone(1, []int32{2}); !gone || next != 2 || m.relayOff() {
		t.Fatalf("handover to %d, %v, relay off %v", next, gone, m.relayOff())
	}
}

// TestMempoolFeedSilent checks that a feed that sends no filter while
// transactions are announced to us is replaced after mpFeedProveWait, isn't
// taken again while another peer is left, and that with none left there is
// no feed.  A quiet mempool, with nothing announced, replaces nothing.
func TestMempoolFeedSilent(t *testing.T) {
	clock := &feedClock{now: intervalClock()}
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) {}, clock.get)
	m.offer(1)

	clock.now = clock.now.Add(time.Hour)
	if m.rotateDue() {
		t.Fatal("a feed was replaced while nothing was announced")
	}
	m.announcedTx()
	clock.now = clock.now.Add(mpFeedProveWait - time.Second)
	if m.rotateDue() {
		t.Fatal("a feed was replaced before its time to prove itself")
	}
	clock.now = clock.now.Add(time.Second)
	if id, changed := m.rotate([]int32{1, 2}); !changed || id != 2 {
		t.Fatalf("rotated to %d, %v; want 2", id, changed)
	}
	m.announcedTx()
	clock.now = clock.now.Add(mpFeedProveWait)
	if id, changed := m.rotate([]int32{1, 2}); !changed || id != noFeed {
		t.Fatalf("rotated to %d, %v; want no feed, as both were silent", id, changed)
	}
	if m.offer(1) || m.offer(2) {
		t.Fatal("a silent feed was taken again")
	}
	if !m.offer(3) {
		t.Fatal("a new peer wasn't taken as the feed")
	}

	// A peer that leaves is forgotten.
	m.feedGone(1, nil)
	if _, ok := m.silent[1]; ok {
		t.Fatal("a peer that left is still remembered")
	}
}

// TestMempoolFeedRotates checks that a feed that sends filters is replaced by
// another peer between two thirds and four thirds of mpFeedRotate, and is
// kept, with its intervals, when it is the only peer.
func TestMempoolFeedRotates(t *testing.T) {
	clock := &feedClock{now: intervalClock()}
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) {}, clock.get)
	m.offer(1)
	msg, _ := intervalOf(t, 1, 1, []byte{0x53, 0x02}, 1)
	mustOnFilter(t, m, 1, msg)

	clock.now = clock.now.Add(mpFeedRotate * 2 / 3)
	if m.rotateDue() {
		t.Fatal("a feed was replaced too soon")
	}
	clock.now = clock.now.Add(mpFeedRotate * 2 / 3)
	if id, changed := m.rotate([]int32{1}); changed || id != noFeed {
		t.Fatalf("the only peer was replaced by %d", id)
	}
	if feed, _ := m.feed(); feed != 1 || !m.relayOff() || len(m.intervals) != 1 {
		t.Fatalf("the only feed wasn't kept as it was: feed %d", feed)
	}
	clock.now = clock.now.Add(mpFeedRotate * 4 / 3)
	if id, changed := m.rotate([]int32{1, 2}); !changed || id != 2 {
		t.Fatalf("rotated to %d, %v; want 2", id, changed)
	}
	if _, ok := m.silent[1]; ok {
		t.Fatal("a feed that served was taken as silent")
	}
}

// TestMempoolIntervalWaitScales checks that an asked run goes back to pending
// only once the wait for its size has passed since the last transactions the
// feed sent, so a large run that is still arriving isn't asked for twice.
func TestMempoolIntervalWaitScales(t *testing.T) {
	if wait := mpTxsWaitFor(10000); wait < 4*time.Minute {
		t.Fatalf("a run of 10000 transactions is waited for %v", wait)
	}
	other := []byte{0x53, 0x42}
	clock := &feedClock{now: intervalClock()}
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) {}, clock.get)
	m.setFeed(1)
	var replies []*wire.MsgMpTxs
	for seq := uint32(1); seq <= 3; seq++ {
		msg, reply := intervalOf(t, seq, 1, other, seq)
		mustOnFilter(t, m, 1, msg)
		replies = append(replies, reply)
	}
	requireRun(t, m.next(allowMempoolScore), 1, 3)
	wait := mpTxsWaitFor(3)

	// The first answer arrives late, and the rest wait from it.
	clock.now = clock.now.Add(wait - time.Second)
	if err := m.onTxs(1, replies[0]); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(wait - time.Second)
	if got := m.next(allowMempoolScore); got != nil {
		t.Fatalf("asked again while answers still arrive: %v", got)
	}
	clock.now = clock.now.Add(time.Second)
	requireRun(t, m.next(allowMempoolScore), 2, 3)
}

// TestMempoolIntervalGivesUp checks that an interval asked mpTxsTries times
// without an answer is given up, and so is one the feed's newer intervals
// have pushed out of the hour a node keeps.
func TestMempoolIntervalGivesUp(t *testing.T) {
	other := []byte{0x53, 0x43}
	clock := &feedClock{now: intervalClock()}
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) {}, clock.get)
	m.setFeed(1)
	msg, _ := intervalOf(t, 1, 1, other, 1)
	mustOnFilter(t, m, 1, msg)
	for try := 1; try <= mpTxsTries; try++ {
		requireRun(t, m.next(allowMempoolScore), 1, 1)
		clock.now = clock.now.Add(mpTxsWaitFor(1))
	}
	if got := m.next(allowMempoolScore); got != nil {
		t.Fatalf("asked a %d time: %v", mpTxsTries+1, got)
	}

	// Interval 2 waits for the score; then interval 721 arrives.
	second, _ := intervalOf(t, 2, 1, other, 2)
	mustOnFilter(t, m, 1, second)
	if got := m.next(func() bool { return false }); got != nil {
		t.Fatal("asked without room in the score")
	}
	latest, _ := intervalOf(t, 2+mpIntervalsKept, 1, other, 3)
	mustOnFilter(t, m, 1, latest)
	requireRun(t, m.next(allowMempoolScore), 2+mpIntervalsKept, 2+mpIntervalsKept)
}

// TestMempoolIntervalTxIDs checks that a full transaction listed with another
// ID than its own is refused, even when the IDs give the announced hash.
func TestMempoolIntervalTxIDs(t *testing.T) {
	other := []byte{0x53, 0x44}
	var delivered int
	m := newMempoolIntervals(10, func() [][]byte { return nil },
		func(*bchutil.Tx) { delivered++ }, intervalClock)
	m.setFeed(1)
	msg, reply := intervalOf(t, 1, 2, other, 1)
	mustOnFilter(t, m, 1, msg)
	requireRun(t, m.next(allowMempoolScore), 1, 1)
	swapped := *reply
	swapped.Txs = slices.Clone(reply.Txs)
	swapped.Txs[0].Tx = intervalTx(other, 99)
	if err := m.onTxs(1, &swapped); !errors.Is(err, errMpTxs) || delivered != 0 {
		t.Fatalf("another transaction under a listed ID: %v, %d delivered", err, delivered)
	}
	if err := m.onTxs(1, reply); err != nil || delivered != 2 {
		t.Fatalf("the true answer: %v, %d delivered", err, delivered)
	}
}

// TestMempoolIntervalNoMatch checks that an interval fetched because its
// filter matched, whose transactions hold nothing we watch, is reported, and
// that one that holds something, a small one, and one whose transactions
// are only IDs are told apart.
func TestMempoolIntervalNoMatch(t *testing.T) {
	watched := []byte{0x52, 0x45}
	key := builder.ScriptKey(watched)
	for _, test := range []struct {
		name    string
		n       int
		ours    bool
		idsOnly bool
		want    error
	}{
		{"a match that holds ours", 12, true, false, nil},
		{"a match that holds nothing of ours", 12, false, false, errMpTxsNoMatch},
		{"a match sent as IDs only", 12, true, true, errMpTxsNoMatch},
		{"a small interval", 3, false, false, nil},
	} {
		m := newMempoolIntervals(10, func() [][]byte { return [][]byte{key[:]} },
			func(*bchutil.Tx) {}, intervalClock)
		m.ours = func(*bchutil.Tx) bool { return test.ours }
		m.setFeed(1)
		msg, reply := intervalOf(t, 1, test.n, watched, 1)
		mustOnFilter(t, m, 1, msg)
		requireRun(t, m.next(allowMempoolScore), 1, 1)
		if test.idsOnly {
			for i := range reply.Txs {
				reply.Txs[i].Tx = nil
			}
		}
		if err := m.onTxs(1, reply); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", test.name, err, test.want)
		}
	}
}

// feedRemote records what a remote peer of the feed tests is sent.
type feedRemote struct {
	peer       *peer.Peer
	sendFilter chan struct{}
	feeFilter  chan int64
	getTxs     chan *wire.MsgGetMpTxs
}

// connectFeedPeer connects an outbound peer of s to a remote peer that
// serves filters and records the sendmpfilter, feefilter and getmptxs
// messages it gets.
func connectFeedPeer(t *testing.T, s *ChainService) (*ServerPeer, *feedRemote) {
	t.Helper()
	remote := &feedRemote{
		sendFilter: make(chan struct{}, 10),
		feeFilter:  make(chan int64, 10),
		getTxs:     make(chan *wire.MsgGetMpTxs, 10),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	remotes := make(chan *peer.Peer, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p := peer.NewInboundPeer(&peer.Config{
			ChainParams: &s.chainParams,
			Services:    wire.SFNodeNetwork | wire.SFNodeCF,
			Listeners: peer.MessageListeners{
				OnSendMpFilter: func(*peer.Peer, *wire.MsgSendMpFilter) {
					remote.sendFilter <- struct{}{}
				},
				OnFeeFilter: func(_ *peer.Peer, msg *wire.MsgFeeFilter) {
					remote.feeFilter <- msg.MinFee
				},
				OnGetMpTxs: func(_ *peer.Peer, msg *wire.MsgGetMpTxs) {
					remote.getTxs <- msg
				},
			},
			TstAllowSelfConnection: true,
		})
		p.AssociateConnection(conn)
		remotes <- p
	}()

	sp := newServerPeer(s, false)
	cfg := newPeerConfig(sp)
	cfg.NewestBlock = nil
	cfg.TstAllowSelfConnection = true
	sp.Peer, err = peer.NewOutboundPeer(cfg, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sp.associate(conn)
	t.Cleanup(sp.Disconnect)
	select {
	case <-s.newPeers:
	case <-time.After(10 * time.Second):
		t.Fatal("version handshake timed out")
	}
	remote.peer = <-remotes
	return sp, remote
}

// expect waits for a value on ch.
func expect[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s", what)
		var none T
		return none
	}
}

// expectNone checks that nothing arrives on ch for a moment.
func expectNone[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("unexpected %s: %v", what, v)
	case <-time.After(200 * time.Millisecond):
	}
}

// newFeedTestService returns a service on script filters with an interval
// watcher on clock, whose peer handler answers for peers.
func newFeedTestService(t *testing.T, clock *feedClock,
	peers func() []*ServerPeer) (*ChainService, *recordedBans) {

	t.Helper()
	s, bans := newPeerTestService(t)
	s.filterType = wire.GCSFilterScripts
	s.mempool = NewMempool()
	s.mempoolRequests = newMempoolRequester(s.Peers, func() bool { return false }, s.quit)
	s.mempoolIntervals = newMempoolIntervals(10, s.mempoolWatchEntries,
		s.deliverMempoolTx, clock.get)
	s.mempoolIntervals.ours = s.mempoolTxIsOurs
	s.sendMessage = func(sp *ServerPeer, msg wire.Message) { sp.QueueMessage(msg, nil) }
	go func() {
		for {
			select {
			case q := <-s.query:
				if msg, ok := q.(getPeersMsg); ok {
					msg.reply <- peers()
				}
			case <-s.quit:
				return
			}
		}
	}()
	return s, bans
}

// TestMempoolFeedOverTheWire checks the feed with peers over connections: the
// first one is asked for interval filters while peers still announce
// transactions; its first filter turns announcements off for every peer,
// with a fee filter, and has its small interval asked for; a rotation hands
// the feed to the other peer and turns announcements on again until it has
// sent a filter; the feed that disconnects is replaced by the peer left; and
// a feed that sends transactions other than those it announced is banned.
func TestMempoolFeedOverTheWire(t *testing.T) {
	clock := &feedClock{now: time.Now()}
	var peers []*ServerPeer
	s, bans := newFeedTestService(t, clock, func() []*ServerPeer { return peers })
	first, firstRemote := connectFeedPeer(t, s)
	second, secondRemote := connectFeedPeer(t, s)
	peers = []*ServerPeer{first, second}

	// The first peer is the feed, and peers still announce.
	s.offerMempoolFeed(first)
	s.offerMempoolFeed(second)
	expect(t, firstRemote.sendFilter, "sendmpfilter to the first peer")
	expectNone(t, secondRemote.sendFilter, "sendmpfilter to the second peer")
	expectNone(t, firstRemote.feeFilter, "feefilter before a filter came")
	if s.mempoolFeed.Load() != first {
		t.Fatal("the feed peer isn't kept")
	}

	// Its first filter turns announcements off, and its interval is
	// asked for.
	msg, reply := intervalOf(t, 7, 1, []byte{0x53, 0x61}, 1)
	firstRemote.peer.QueueMessage(msg, nil)
	for _, remote := range []*feedRemote{firstRemote, secondRemote} {
		if fee := expect(t, remote.feeFilter, "feefilter after a filter"); fee != bchutil.MaxSatoshi {
			t.Fatalf("fee filter %d, want one above any fee", fee)
		}
	}
	get := expect(t, firstRemote.getTxs, "getmptxs")
	if get.FirstSeq != 7 || get.LastSeq != 7 {
		t.Fatalf("asked for %d to %d", get.FirstSeq, get.LastSeq)
	}
	firstRemote.peer.QueueMessage(reply, nil)

	// A peer that connects now is told not to announce.
	third, thirdRemote := connectFeedPeer(t, s)
	s.offerMempoolFeed(third)
	if fee := expect(t, thirdRemote.feeFilter, "feefilter to a new peer"); fee != bchutil.MaxSatoshi {
		t.Fatalf("fee filter %d to a new peer", fee)
	}
	third.Disconnect()

	// A rotation hands the feed over and turns announcements on again.
	clock.now = clock.now.Add(2 * mpFeedRotate)
	s.rotateMempoolFeed()
	expect(t, secondRemote.sendFilter, "sendmpfilter to the second peer")
	for _, remote := range []*feedRemote{firstRemote, secondRemote} {
		if fee := expect(t, remote.feeFilter, "feefilter after a rotation"); fee != 0 {
			t.Fatalf("fee filter %d after a rotation, want 0", fee)
		}
	}
	if s.mempoolFeed.Load() != second {
		t.Fatal("the new feed isn't kept")
	}

	// The feed disconnects, by a request that removed it from the peers,
	// and the peer left becomes the feed.
	state := &peerState{
		persistentPeers: make(map[int32]*ServerPeer),
		outboundPeers:   map[int32]*ServerPeer{first.ID(): first},
		outboundGroups:  make(map[string]int),
	}
	s.handleDonePeerMsg(state, second)
	expect(t, firstRemote.sendFilter, "sendmpfilter to the peer left")
	if s.mempoolFeed.Load() != first {
		t.Fatal("the peer left isn't the feed")
	}

	// It announces an interval and sends other transactions for it.
	msg, reply = intervalOf(t, 9, 1, []byte{0x53, 0x62}, 5)
	firstRemote.peer.QueueMessage(msg, nil)
	expect(t, firstRemote.getTxs, "getmptxs from the new feed")
	reply.Txs[0].Tx = intervalTx([]byte{0x53, 0x63}, 77)
	reply.Txs[0].TxID = reply.Txs[0].Tx.TxHash()
	firstRemote.peer.QueueMessage(reply, nil)
	deadline := time.Now().Add(5 * time.Second)
	for len(bans.bans()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for _, reason := range bans.bans() {
		if reason != banman.InvalidMempoolInterval {
			t.Fatalf("banned for %v", reason)
		}
	}
	if len(bans.bans()) != 1 {
		t.Fatalf("bans %v, want the feed's", bans.bans())
	}
}

// TestMempoolFeedSilentOverTheWire checks that a feed that sends no filter
// while a transaction is announced is replaced once its time is up, and that
// the ticker asks the feed for an interval the score had no room for when
// its filter came, once the score has room.
func TestMempoolFeedSilentOverTheWire(t *testing.T) {
	clock := &feedClock{now: time.Now()}
	var peers []*ServerPeer
	s, _ := newFeedTestService(t, clock, func() []*ServerPeer { return peers })
	first, firstRemote := connectFeedPeer(t, s)
	second, secondRemote := connectFeedPeer(t, s)
	peers = []*ServerPeer{first, second}

	s.offerMempoolFeed(first)
	expect(t, firstRemote.sendFilter, "sendmpfilter to the first peer")
	s.mempoolIntervals.announcedTx()
	clock.now = clock.now.Add(mpFeedProveWait)
	s.rotateMempoolFeed()
	expect(t, secondRemote.sendFilter, "sendmpfilter to the second peer")
	if s.mempoolFeed.Load() != second {
		t.Fatal("the silent feed was kept")
	}

	// A filter arrives while the score has no room.
	if !second.mempoolScore.tryReserve(0, maxMempoolBanScore, maxMempoolBanScore) {
		t.Fatal("unable to hold the score")
	}
	msg, _ := intervalOf(t, 3, 1, []byte{0x53, 0x64}, 1)
	secondRemote.peer.QueueMessage(msg, nil)
	expect(t, secondRemote.feeFilter, "feefilter after the filter")
	expectNone(t, secondRemote.getTxs, "getmptxs without room in the score")

	// The ticker asks once there is room.
	second.mempoolScore.release(maxMempoolBanScore)
	s.wg.Add(1)
	go s.serveMempoolIntervals()
	get := expect(t, secondRemote.getTxs, "getmptxs from the ticker")
	if get.FirstSeq != 3 {
		t.Fatalf("the ticker asked for %d", get.FirstSeq)
	}
}

// TestScriptFiltersKeepTxRelay checks that on script filters a peer is asked
// to announce transactions in the version message, as a feed has yet to
// prove that it sends interval filters, and that blocks only mode isn't.
func TestScriptFiltersKeepTxRelay(t *testing.T) {
	s := &ChainService{filterType: wire.GCSFilterScripts}
	if newPeerConfig(newServerPeer(s, false)).DisableRelayTx {
		t.Error("script filters turned announcements off at the handshake")
	}
	s.blocksOnly = true
	if !newPeerConfig(newServerPeer(s, false)).DisableRelayTx {
		t.Error("blocks only mode asked for announcements")
	}
}

// TestMempoolWatchEntries checks that a large interval is matched with the
// addresses given to NotifyMempoolReceived too, and that a transaction paying
// one of them is ours.
func TestMempoolWatchEntries(t *testing.T) {
	s := &ChainService{mempool: NewMempool(),
		mempoolRequests: newMempoolRequester(nil, nil, nil)}
	addr, err := bchutil.NewAddressPubKeyHash(make([]byte, 20), &s.chainParams)
	if err != nil {
		t.Fatal(err)
	}
	s.mempool.NotifyReceived([]bchutil.Address{addr})
	script := []byte{0x76, 0xa9, 0x14}
	script = append(append(script, make([]byte, 20)...), 0x88, 0xac)
	key := builder.ScriptKey(script)
	if entries := s.mempoolWatchEntries(); len(entries) != 1 || string(entries[0]) != string(key[:]) {
		t.Fatalf("entries %x, want the address's script key", entries)
	}
	tx := intervalTx(script, 1)
	if !s.mempoolTxIsOurs(bchutil.NewTx(tx)) {
		t.Error("a payment to a watched address isn't ours")
	}
	if s.mempoolTxIsOurs(bchutil.NewTx(intervalTx([]byte{0x51}, 2))) {
		t.Error("a payment to another script is ours")
	}
}
