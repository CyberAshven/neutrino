package neutrino

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/neutrino/cache/lru"
	"github.com/gcash/neutrino/filterdb"
	"github.com/gcash/neutrino/headerfs"
)

// sortedLeaves returns leaves in the order of an entry tree.
func sortedLeaves(leaves []builder.ScriptLeaf) []builder.ScriptLeaf {
	slices.SortFunc(leaves, func(a, b builder.ScriptLeaf) int {
		return compareScriptLeaves(&a, &b)
	})
	return leaves
}

// TestFetchScriptLeavesOversized checks that the leaves of a tree are fetched
// from a node that doesn't answer for a range larger than it sends in one
// message: by splitting a run that gets no answer into one the proofs of its
// first leaf and of the leaf the most a run fits after it show fits.  That
// holds when the leaves of a run spread over many keys, when many share a
// long prefix, as a block made for it has, and when one key has more leaves
// than we take a run to fit but fewer than the node sends.  A key with more
// leaves than the node sends can't be fetched, and the peer is not blamed.
func TestFetchScriptLeavesOversized(t *testing.T) {
	c := newDisputeChain(t)
	hash := c.block.header.BlockHash()
	defer func(n uint32, most func() uint64) {
		scriptLeavesPerRange, maxRangeLeaves = n, most
	}(scriptLeavesPerRange, maxRangeLeaves)

	// One run would hold the whole tree.
	scriptLeavesPerRange = 1 << 20
	maxRangeLeaves = func() uint64 { return 3 }

	ground := func(n int, prefix []byte) []builder.ScriptLeaf {
		var leaves []builder.ScriptLeaf
		for i := 0; i < n; i++ {
			leaf := builder.ScriptLeaf{TxIndex: uint32(i), Kind: builder.ScriptLeafOutput}
			copy(leaf.Key[:], prefix)
			leaf.Key[31] = byte(i)
			leaves = append(leaves, leaf)
		}
		return leaves
	}
	oneKey := func(n int, key byte) []builder.ScriptLeaf {
		var leaves []builder.ScriptLeaf
		for i := 0; i < n; i++ {
			leaves = append(leaves, builder.ScriptLeaf{
				Key: [32]byte{key, 0x01}, TxIndex: uint32(i),
				Kind: builder.ScriptLeafOutput,
			})
		}
		return leaves
	}
	prefix := bytes.Repeat([]byte{0x5a}, 30)

	tests := []struct {
		name   string
		leaves []builder.ScriptLeaf

		// nodeMost is the most leaves the node sends in a cfrange.
		nodeMost int
		wantErr  error
	}{{
		name:     "the block's leaves",
		leaves:   slices.Clone(c.leaves),
		nodeMost: 4,
	}, {
		name:     "leaves that share 240 bits",
		leaves:   sortedLeaves(append(ground(9, prefix), c.leaves...)),
		nodeMost: 4,
	}, {
		name:     "one key with more leaves than we take a run to fit",
		leaves:   sortedLeaves(append(oneKey(4, 0x80), c.leaves...)),
		nodeMost: 4,
	}, {
		name:     "one key with more leaves than the node sends",
		leaves:   sortedLeaves(append(oneKey(6, 0x80), c.leaves...)),
		nodeMost: 4,
		wantErr:  errNoAnswer,
	}}
	for _, test := range tests {
		p := &disputePeer{chain: c, leaves: test.leaves, maxRangeLeaves: test.nodeMost}
		leaves, err := fetchScriptLeaves("peer", hash, p.root(),
			func(_ string, bits uint16, prefix [32]byte) (*wire.MsgCFRange, error) {
				return p.answerRange(bits, prefix)
			},
			func(_ string, index uint32) (*wire.MsgCFProof, error) {
				return p.answer(index)
			})
		if test.wantErr != nil {
			if !errors.Is(err, test.wantErr) {
				t.Errorf("%s: got %v, want %v", test.name, err, test.wantErr)
			}
			continue
		}
		if err != nil || !slices.Equal(leaves, test.leaves) {
			t.Errorf("%s: %d leaves of %d, %v", test.name, len(leaves),
				len(test.leaves), err)
		}
		if p.asked == 0 {
			t.Errorf("%s: no run was split", test.name)
		}
	}

	// A peer that stops answering is not at fault, and neither is one
	// that doesn't answer for a run that fits a message.
	for name, change := range map[string]func(p *disputePeer){
		"stops answering": func(p *disputePeer) {
			p.tamperRange = func(*wire.MsgCFRange) {
				if p.askedRanges > 1 {
					p.silent = true
				}
			}
		},
		"no answer for a small run": func(p *disputePeer) { p.maxRangeLeaves = 1 },
	} {
		p := c.honest()
		p.maxRangeLeaves = 4
		change(p)
		_, err := fetchScriptLeaves("peer", hash, p.root(),
			func(_ string, bits uint16, prefix [32]byte) (*wire.MsgCFRange, error) {
				return p.answerRange(bits, prefix)
			},
			func(_ string, index uint32) (*wire.MsgCFProof, error) {
				return p.answer(index)
			})
		if !errors.Is(err, errNoAnswer) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	// Proofs that don't fit the tree the ranges give are the peer's fault.
	p := c.honest()
	p.maxRangeLeaves = 4
	p.tamper = func(msg *wire.MsgCFProof) { msg.LeafBranch[0][0] ^= 1 }
	_, err := fetchScriptLeaves("peer", hash, p.root(),
		func(_ string, bits uint16, prefix [32]byte) (*wire.MsgCFRange, error) {
			return p.answerRange(bits, prefix)
		},
		func(_ string, index uint32) (*wire.MsgCFProof, error) {
			return p.answer(index)
		})
	if !errors.Is(err, errScriptProof) {
		t.Errorf("a proof that doesn't fit: got %v", err)
	}
}

// TestSettleScriptFiltersNoAnswer checks that peers that serve the true root
// in front of different filters, none of which gives the leaves, are not
// found at fault, and that the dispute is not taken as settled: neither when
// they don't answer at all nor when the leaves of one key are more than a
// node sends.  One honest peer that gives them is enough to find the liar.
func TestSettleScriptFiltersNoAnswer(t *testing.T) {
	c := newDisputeChain(t)
	defer func(n uint32, most func() uint64) {
		scriptLeavesPerRange, maxRangeLeaves = n, most
	}(scriptLeavesPerRange, maxRangeLeaves)
	scriptLeavesPerRange = 4

	wrongFilter := func(p *disputePeer) *disputePeer {
		p.filter = []byte{0x00}
		return p
	}

	// Neither answers.
	honest, liar := c.honest(), wrongFilter(c.honest())
	honest.silent, liar.silent = true, true
	bad, err := c.settleFiltersAll(t, map[string]*disputePeer{
		"honest": honest, "liar": liar,
	})
	if !errors.Is(err, errScriptDisputeUnsettled) || len(bad) != 0 {
		t.Errorf("no answers: at fault %v, %v", bad, err)
	}

	// The honest peer is behind and doesn't answer, and the liar gives
	// the leaves, which show its own filter wrong.
	honest, liar = c.honest(), wrongFilter(c.honest())
	honest.silent = true
	bad, err = c.settleFiltersAll(t, map[string]*disputePeer{
		"honest": honest, "liar": liar,
	})
	if err != nil || !slices.Equal(bad, []string{"liar"}) {
		t.Errorf("a silent honest peer: at fault %v, %v", bad, err)
	}

	// The leaves of one key don't fit a message.
	heavy := sortedLeaves(append(slices.Clone(c.leaves), func() []builder.ScriptLeaf {
		var leaves []builder.ScriptLeaf
		for i := 0; i < 6; i++ {
			leaves = append(leaves, builder.ScriptLeaf{Key: [32]byte{0x80},
				TxIndex: uint32(i), Kind: builder.ScriptLeafOutput})
		}
		return leaves
	}()...))
	maxRangeLeaves = func() uint64 { return 3 }
	honest = &disputePeer{chain: c, leaves: heavy, maxRangeLeaves: 4}
	liar = wrongFilter(&disputePeer{chain: c, leaves: heavy, maxRangeLeaves: 4})
	bad, err = c.settleFiltersAll(t, map[string]*disputePeer{
		"honest": honest, "liar": liar,
	})
	if !errors.Is(err, errScriptDisputeUnsettled) || len(bad) != 0 {
		t.Errorf("a key too heavy for a message: at fault %v, %v", bad, err)
	}

	// Shutting down ends it.
	honest, liar = c.honest(), wrongFilter(c.honest())
	honest.quitting, liar.quitting = true, true
	if _, err := c.settleFiltersAll(t, map[string]*disputePeer{
		"honest": honest, "liar": liar,
	}); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("shutting down: %v", err)
	}

	// A peer with another root that doesn't answer leaves it unsettled,
	// even though the peers left agree.
	other := c.liar(true, func(l []builder.ScriptLeaf) []builder.ScriptLeaf { return l[1:] })
	other.silent = true
	bad, err = c.settleFiltersAll(t, map[string]*disputePeer{
		"a": c.honest(), "b": c.honest(), "other": other,
	})
	if !errors.Is(err, errScriptDisputeUnsettled) || len(bad) != 0 {
		t.Errorf("a silent peer with another root: at fault %v, %v", bad, err)
	}
}

// TestReplyWaitLeft checks that a wait ends quiet after the request, is
// extended while bytes arrive, and never passes most.
func TestReplyWaitLeft(t *testing.T) {
	w := replyWait{quiet: 30 * time.Second, most: 10 * time.Minute}
	asked := time.Unix(1000, 0)
	at := func(d time.Duration) time.Time { return asked.Add(d) }

	tests := []struct {
		name      string
		last, now time.Time
		want      time.Duration
	}{
		{"just asked", time.Time{}, asked, 30 * time.Second},
		{"silent", at(-time.Hour), at(30 * time.Second), 0},
		{"a byte a while ago", at(20 * time.Second), at(30 * time.Second), 20 * time.Second},
		{"bytes keep coming", at(9 * time.Minute), at(9*time.Minute + time.Second), 29 * time.Second},
		{"but not past most", at(599 * time.Second), at(599 * time.Second), time.Second},
		{"over", at(10 * time.Minute), at(10 * time.Minute), 0},
	}
	for _, test := range tests {
		if got := w.left(asked, test.last, test.now); got != test.want {
			t.Errorf("%s: %v left, want %v", test.name, got, test.want)
		}
	}
}

// TestAskAgain checks that a request that isn't answered is made again, up to
// the tries, that an answer or another error ends it, and that shutting down
// during a pause does.
func TestAskAgain(t *testing.T) {
	never := make(chan struct{})
	answerAfter := func(n int) (func() (int, error), *int) {
		calls := 0
		return func() (int, error) {
			calls++
			if calls <= n {
				return 0, errNoAnswer
			}
			return 7, nil
		}, &calls
	}

	ask, calls := answerAfter(1)
	if got, err := askAgain(2, time.Millisecond, never, ask); err != nil || got != 7 || *calls != 2 {
		t.Errorf("one try ignored: %d, %v after %d calls", got, err, *calls)
	}
	ask, calls = answerAfter(2)
	if _, err := askAgain(2, time.Millisecond, never, ask); !errors.Is(err, errNoAnswer) || *calls != 2 {
		t.Errorf("all tries ignored: %v after %d calls", err, *calls)
	}
	wrong, n := errors.New("wrong"), 0
	if _, err := askAgain(3, time.Millisecond, never, func() (int, error) {
		n++
		return 0, wrong
	}); !errors.Is(err, wrong) || n != 1 {
		t.Errorf("another error: %v after %d calls", err, n)
	}
	quit := make(chan struct{})
	close(quit)
	ask, calls = answerAfter(5)
	if _, err := askAgain(3, time.Hour, quit, ask); !errors.Is(err, ErrShuttingDown) || *calls != 1 {
		t.Errorf("shutting down: %v after %d calls", err, *calls)
	}
}

// TestProbeVerdict checks that a peer is dropped only when it serves another
// genesis script filter, or when it is current and doesn't answer the probes
// in a row, and that one behind us, or any while we aren't synced, is asked
// again later.
func TestProbeVerdict(t *testing.T) {
	tests := []struct {
		name        string
		answer      probeAnswer
		current     bool
		silent      int
		again, drop bool
	}{
		{"serves", probeServes, true, 0, false, false},
		{"serves, behind", probeServes, false, 0, false, false},
		{"another filter", probeOther, true, 0, false, true},
		{"another filter, behind", probeOther, false, 0, false, true},
		{"silent, behind", probeSilent, false, 0, true, false},
		{"silent once, current", probeSilent, true, 1, true, false},
		{"silent twice, current", probeSilent, true, scriptFilterProbeTries, false, true},
	}
	for _, test := range tests {
		again, drop := probeVerdict(test.answer, test.current, test.silent)
		if again != test.again || drop != test.drop {
			t.Errorf("%s: again %v drop %v, want %v %v", test.name, again,
				drop, test.again, test.drop)
		}
	}
}

// TestFilterTooManyValues checks that a served script filter whose N is more
// than its bytes can hold is refused before anything is sized by N, and that
// reading the values of such a filter fails the same way.
func TestFilterTooManyValues(t *testing.T) {
	c := newDisputeChain(t)
	blockHash := c.block.header.BlockHash()
	filter, err := scriptFilterOfLeaves(&blockHash, c.leaves)
	if err != nil {
		t.Fatal(err)
	}
	data, err := filter.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	most := uint32(len(data) * 8 / (builder.DefaultP + 1))

	served := func(n uint32) []byte {
		var buf bytes.Buffer
		buf.Write(make([]byte, chainhash.HashSize))
		if err := wire.WriteVarInt(&buf, 0, uint64(n)); err != nil {
			t.Fatal(err)
		}
		buf.Write(data)
		return buf.Bytes()
	}
	if _, _, err := parseServedFilter(wire.GCSFilterScripts, served(most)); err != nil {
		t.Errorf("N at the most the bytes hold: %v", err)
	}
	for _, n := range []uint32{most + 1, 1<<32 - 1} {
		if _, _, err := parseServedFilter(wire.GCSFilterScripts, served(n)); !errors.Is(err, errFilterTooManyValues) {
			t.Errorf("N = %d: %v", n, err)
		}
		huge, err := gcs.FromBytes(n, builder.DefaultP, builder.DefaultM, data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gcsFilterValues(huge); !errors.Is(err, errFilterTooManyValues) {
			t.Errorf("values of N = %d: %v", n, err)
		}
	}
}

// TestVerifyScriptBlockFilterHeldOnly checks that a block is checked against
// the script filter held for it, in the cache or the database, and that
// without one nothing is asked of peers, so that GetBlock doesn't wait on
// the network for it.
func TestVerifyScriptBlockFilterHeldOnly(t *testing.T) {
	bm, hdrStore, cfStore, cleanUp, err := setupBlockManager()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp()
	cs := bm.server
	cs.blockManager = bm
	cs.filterType = wire.GCSFilterScripts
	cs.FilterCache = lru.NewCache(1 << 20)
	cs.FilterDB = newTestFilterDB(t)
	cs.quit = make(chan struct{})
	asked := false
	cs.queryPeers = func(wire.Message, func(*ServerPeer, wire.Message,
		chan<- struct{}), ...QueryOption) {

		asked = true
	}

	// The block and a filter header for it are synced at height 1, so a
	// filter for it could be fetched.
	c := newDisputeChain(t)
	blockHash := c.block.header.BlockHash()
	err = hdrStore.WriteHeaders(headerfs.BlockHeader{
		BlockHeader: &c.block.header, Height: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cfStore.WriteHeaders(headerfs.FilterHeader{
		HeaderHash: blockHash, FilterHash: chainhash.Hash{0x01}, Height: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	msgBlock := wire.NewMsgBlock(&c.block.header)
	for _, tx := range c.block.txs {
		msgBlock.Transactions = append(msgBlock.Transactions, tx.MsgTx())
	}
	block := bchutil.NewBlock(msgBlock)

	if err := cs.verifyScriptBlockFilter(block, 1); err != nil || asked {
		t.Fatalf("without a filter held: %v, peers asked %v", err, asked)
	}

	// The filter held is checked: the true one passes, and one without
	// the block's outputs doesn't.
	right, err := scriptFilterOfLeaves(&blockHash, c.leaves)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := scriptFilterOfLeaves(&blockHash, c.leaves[:2])
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		filter *gcs.Filter
		want   error
	}{{right, nil}, {wrong, ErrBlockFilterMismatch}} {
		if _, err := cs.putFilterToCache(&blockHash, filterdb.ScriptFilter, test.filter); err != nil {
			t.Fatal(err)
		}
		if err := cs.verifyScriptBlockFilter(block, 1); !errors.Is(err, test.want) || asked {
			t.Errorf("with a filter held: %v, want %v; peers asked %v", err,
				test.want, asked)
		}
	}
}
