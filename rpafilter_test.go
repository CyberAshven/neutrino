package neutrino

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs/builder"
)

// rpaTestPeer serves the input prefix filters of a chain, as a node does, or
// changed by edit.
type rpaTestPeer struct {
	silent bool

	// edit, when set, changes the filter a peer serves for a height.
	edit func(height int32, filter []byte) []byte
}

// rpaTestChain is a chain of blocks with the peers that serve its filters.
type rpaTestChain struct {
	mtx    sync.Mutex
	blocks []*bchutil.Block
	peers  map[string]*rpaTestPeer
	banned []string

	// known holds every block a peer can serve, by hash, the blocks of a
	// chain that a reorg replaced too.
	known map[chainhash.Hash]*bchutil.Block

	// downloads counts the blocks downloaded, by height.
	downloads map[int32]int

	// afterHashes, when set, runs after the hashes of a run were read,
	// and offChain, while above zero, has that many checks find the run
	// gone from the chain.
	afterHashes func()
	offChain    int

	// failBlock, when set, makes downloading the block at that height fail.
	failBlock int32
}

func (c *rpaTestChain) tip() (int32, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return int32(len(c.blocks) - 1), nil
}

func (c *rpaTestChain) runHashes(start, stop int32) ([]chainhash.Hash, error) {
	c.mtx.Lock()
	var hashes []chainhash.Hash
	for h := start; h <= stop; h++ {
		hashes = append(hashes, *c.blocks[h].Hash())
	}
	after := c.afterHashes
	c.afterHashes = nil
	c.mtx.Unlock()
	if after != nil {
		after()
	}
	return hashes, nil
}

func (c *rpaTestChain) onChain(hash chainhash.Hash, height int32) bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.offChain > 0 {
		c.offChain--
		return false
	}
	return int(height) < len(c.blocks) && *c.blocks[height].Hash() == hash
}

// heightOf returns the height of a block the peers know, in its own chain.
func (c *rpaTestChain) heightOf(hash chainhash.Hash) int32 {
	block, ok := c.known[hash]
	if !ok {
		return -1
	}
	return block.Height()
}

func (c *rpaTestChain) served(peer string, hash chainhash.Hash) []byte {
	block := c.known[hash]
	filter := builder.BuildRPAFilter(block.MsgBlock())
	if p := c.peers[peer]; p.edit != nil {
		filter = p.edit(block.Height(), filter)
	}
	return filter
}

// ancestors returns the hashes of the blocks from start to stop in stop's
// chain.
func (c *rpaTestChain) ancestors(start int32, stop chainhash.Hash) []chainhash.Hash {
	var hashes []chainhash.Hash
	for hash := stop; ; {
		block := c.known[hash]
		hashes = append(hashes, hash)
		if block.Height() == start {
			break
		}
		hash = block.MsgBlock().Header.PrevBlock
	}
	slices.Reverse(hashes)
	return hashes
}

func (c *rpaTestChain) filterHashes(start int32, hashes []chainhash.Hash, _ int,
	_ <-chan struct{}) (map[string]*wire.MsgCFHeaders, error) {

	stop := hashes[len(hashes)-1]
	c.mtx.Lock()
	defer c.mtx.Unlock()
	answers := make(map[string]*wire.MsgCFHeaders)
	for name, p := range c.peers {
		if p.silent || slices.Contains(c.banned, name) {
			continue
		}
		msg := &wire.MsgCFHeaders{FilterType: wire.GCSFilterInputPrefix, StopHash: stop}
		for _, hash := range c.ancestors(start, stop) {
			filterHash := builder.GetRPAFilterHash(c.served(name, hash))
			msg.FilterHashes = append(msg.FilterHashes, &filterHash)
		}
		answers[name] = msg
	}
	return answers, nil
}

func (c *rpaTestChain) filters(peer string, _ int32, hashes []chainhash.Hash,
	_ <-chan struct{}) (map[chainhash.Hash][]byte, error) {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.peers[peer].silent {
		return nil, nil
	}
	got := make(map[chainhash.Hash][]byte)
	for _, hash := range hashes {
		got[hash] = c.served(peer, hash)
	}
	return got, nil
}

func (c *rpaTestChain) block(hash chainhash.Hash, _ <-chan struct{}) (*bchutil.Block, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	h := c.heightOf(hash)
	if h < 0 || h == c.failBlock {
		return nil, errors.New("no such block")
	}
	c.downloads[h]++
	return c.known[hash], nil
}

func (c *rpaTestChain) bad(peer string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if !slices.Contains(c.banned, peer) {
		c.banned = append(c.banned, peer)
	}
}

// mustEncodeRPAFilter codes sorted, distinct values as an input prefix filter.
func mustEncodeRPAFilter(t *testing.T, values []uint16) []byte {
	t.Helper()
	filter, err := builder.EncodeRPAFilter(values)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

// rpaTestTx returns a transaction spending count outpoints of a txid made
// from tag.
func rpaTestTx(tag byte, count int) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for i := 0; i < count; i++ {
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{tag, 0x52}, uint32(i)), nil))
	}
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}, wire.TokenData{}))
	return tx
}

// rpaTestBlocks returns n blocks after prev from height from: block h holds a
// coinbase and, at every third height, a transaction with h%40+1 inputs made
// from tag.
func rpaTestBlocks(prev chainhash.Hash, from, n int, tag byte) []*bchutil.Block {
	var blocks []*bchutil.Block
	for h := from; h < from+n; h++ {
		coinbase := wire.NewMsgTx(1)
		coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
			[]byte{byte(h), byte(h >> 8), tag}))
		coinbase.AddTxOut(wire.NewTxOut(5000, []byte{0x51}, wire.TokenData{}))
		// The header doesn't commit to the transactions here, so the tag
		// tells a fork's blocks apart.
		msg := wire.NewMsgBlock(&wire.BlockHeader{Version: 4, PrevBlock: prev,
			Nonce: uint32(h), Bits: uint32(tag)})
		msg.Transactions = []*wire.MsgTx{coinbase}
		if h%3 == 1 {
			msg.Transactions = append(msg.Transactions, rpaTestTx(byte(h)^tag, h%40+1))
		}
		block := bchutil.NewBlock(msg)
		block.SetHeight(int32(h))
		blocks = append(blocks, block)
		prev = *block.Hash()
	}
	return blocks
}

// newRPATestChain returns a chain of n blocks, served honestly by two peers
// named "honest" and "honest2".
func newRPATestChain(n int) *rpaTestChain {
	c := &rpaTestChain{
		peers:     map[string]*rpaTestPeer{"honest": {}, "honest2": {}},
		known:     make(map[chainhash.Hash]*bchutil.Block),
		downloads: make(map[int32]int),
		failBlock: -1,
	}
	c.blocks = rpaTestBlocks(chainhash.Hash{}, 0, n, 0)
	for _, block := range c.blocks {
		c.known[*block.Hash()] = block
	}
	return c
}

// reorg replaces the blocks from height on with others.
func (c *rpaTestChain) reorg(height int32) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	fork := rpaTestBlocks(*c.blocks[height-1].Hash(), int(height),
		len(c.blocks)-int(height), 0x80)
	for _, block := range fork {
		c.known[*block.Hash()] = block
	}
	c.blocks = append(c.blocks[:height], fork...)
}

// inputsAt returns the values of the inputs of the block at a height.
func (c *rpaTestChain) inputsAt(height int32) []uint16 {
	var values []uint16
	for _, tx := range c.blocks[height].MsgBlock().Transactions[1:] {
		for _, txIn := range tx.TxIn {
			values = append(values, builder.RPAInputValue(txIn))
		}
	}
	return values
}

func (c *rpaTestChain) search(t *testing.T, prefixes []RPAPrefix, start, end int32,
	options ...RPASearchOption) ([]RPAMatch, int32, error) {

	t.Helper()
	var found []RPAMatch
	reached, err := searchRPAPrefixes(c, prefixes, start, end, func(m RPAMatch) bool {
		found = append(found, m)
		return true
	}, nil, nil, options...)
	return found, reached, err
}

// TestSearchRPAPrefixes searches a chain longer than one batch for the full
// value of one input and for a short prefix of another, and checks that it
// finds exactly the blocks with those inputs, in order, downloads only the
// blocks whose filters match, once, says how many peers agreed, and leaves
// out the 31st input of a transaction.
func TestSearchRPAPrefixes(t *testing.T) {
	defer func(batch int32) { rpaFilterBatch = batch }(rpaFilterBatch)
	rpaFilterBatch = 10

	c := newRPATestChain(35)
	target := c.inputsAt(4)[2]
	var runs []int32
	var found []RPAMatch
	reached, err := searchRPAPrefixes(c, []RPAPrefix{{Value: target, Bits: 16}}, 0, 34,
		func(m RPAMatch) bool { found = append(found, m); return true },
		func(height int32, peers int) {
			if peers != 2 {
				t.Errorf("run to %d agreed on by %d peers", height, peers)
			}
			runs = append(runs, height)
		}, nil)
	if err != nil || reached != 34 {
		t.Fatalf("reached %d, %v", reached, err)
	}
	if !slices.Equal(runs, []int32{9, 19, 29, 34}) {
		t.Errorf("progress after runs %v", runs)
	}
	if len(found) == 0 || found[0].Height != 4 || found[0].Peers != 2 {
		t.Fatalf("found %+v, want block 4 first, agreed by 2", found)
	}
	if !slices.IsSortedFunc(found, func(a, b RPAMatch) int { return int(a.Height - b.Height) }) {
		t.Errorf("matches out of order: %+v", found)
	}
	for _, m := range found {
		for _, in := range m.Inputs {
			if in.Value != target || in.Index >= 30 || in.TxIndex == 0 {
				t.Errorf("block %d: input %+v", m.Height, in)
			}
		}
	}
	for h, n := range c.downloads {
		values, _ := builder.DecodeRPAFilter(builder.BuildRPAFilter(c.blocks[h].MsgBlock()))
		if n != 1 || !builder.RPAFilterMatch(values, target, 16) {
			t.Errorf("block %d downloaded %d times, its filter matching %v",
				h, n, builder.RPAFilterMatch(values, target, 16))
		}
	}

	// A 4-bit prefix of an input of block 31 finds block 31 among others.
	short := RPAPrefix{Value: c.inputsAt(31)[0] >> 12, Bits: 4}
	found, _, err = c.search(t, []RPAPrefix{short}, 20, 34)
	if err != nil || !slices.ContainsFunc(found, func(m RPAMatch) bool { return m.Height == 31 }) {
		t.Fatalf("4-bit prefix: found %+v, %v", found, err)
	}

	// Block 31's transaction has 32 inputs: the value of its 31st is in no
	// filter unless another input has it.
	inputs := c.inputsAt(31)
	if len(inputs) != 32 {
		t.Fatalf("block 31 has %d inputs", len(inputs))
	}
	for _, v := range inputs[30:] {
		if slices.Contains(inputs[:30], v) {
			continue
		}
		found, _, err := c.search(t, []RPAPrefix{{Value: v, Bits: 16}}, 31, 31)
		if err != nil || len(found) != 0 {
			t.Errorf("the value %04x of an input past the 30th found %+v, %v", v, found, err)
		}
	}

	// found returning false stops the search at that block.
	reached, err = searchRPAPrefixes(c, []RPAPrefix{{Value: target, Bits: 16}}, 0, 34,
		func(RPAMatch) bool { return false }, nil, nil)
	if err != nil || reached != 4 {
		t.Errorf("stopped at %d, %v; want 4", reached, err)
	}

	// Prefixes that are not ones are refused.
	for _, p := range []RPAPrefix{{0, 0}, {0, 17}, {0x1ff, 8}} {
		if _, _, err := c.search(t, []RPAPrefix{p}, 0, 34); !errors.Is(err, ErrRPAPrefix) {
			t.Errorf("prefix %x/%d: %v", p.Value, p.Bits, err)
		}
	}
}

// TestSearchRPAPrefixesRange checks that a range that isn't in the chain is
// refused before anything is asked, with start-1 as the height reached.
func TestSearchRPAPrefixesRange(t *testing.T) {
	c := newRPATestChain(10)
	for _, r := range [][2]int32{{-1, 5}, {6, 5}, {0, 10}} {
		_, reached, err := c.search(t, []RPAPrefix{{Value: 1, Bits: 16}}, r[0], r[1])
		if !errors.Is(err, ErrRPARange) || reached != r[0]-1 {
			t.Errorf("range %d to %d: reached %d, %v", r[0], r[1], reached, err)
		}
	}
	if len(c.downloads) != 0 {
		t.Errorf("blocks downloaded for ranges refused: %v", c.downloads)
	}
}

// TestSearchRPAPrefixesMinPeers checks that a run needs the filter hashes of
// two peers by default, and of one when the search is set to.
func TestSearchRPAPrefixesMinPeers(t *testing.T) {
	c := newRPATestChain(10)
	c.peers["honest2"].silent = true
	if _, reached, err := c.search(t, []RPAPrefix{{Value: 1, Bits: 16}}, 0, 9); !errors.Is(err, ErrRPAFewPeers) || reached != -1 {
		t.Fatalf("one peer: reached %d, %v", reached, err)
	}
	target := c.inputsAt(7)[0]
	found, _, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 9, RPAMinPeers(1))
	if err != nil || len(found) == 0 || found[0].Peers != 1 {
		t.Fatalf("one peer allowed: found %+v, %v", found, err)
	}
}

// TestSearchRPAPrefixesDisagreement pits honest peers against one that leaves
// the target's value out of a filter, which would hide the payment: the
// disagreement on that block's filter hash is settled by the block, the liar
// is dropped, and the payment is found.
func TestSearchRPAPrefixesDisagreement(t *testing.T) {
	c := newRPATestChain(20)
	target := c.inputsAt(7)[0]
	c.peers["liar"] = &rpaTestPeer{edit: func(height int32, filter []byte) []byte {
		if height != 7 {
			return filter
		}
		values, _ := builder.DecodeRPAFilter(filter)
		values = slices.DeleteFunc(values, func(v uint16) bool { return v == target })
		return mustEncodeRPAFilter(t, values)
	}}
	found, _, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19)
	if err != nil || len(found) == 0 || found[0].Height != 7 {
		t.Fatalf("found %+v, %v", found, err)
	}
	if !slices.Equal(c.banned, []string{"liar"}) {
		t.Errorf("banned %v, want the liar", c.banned)
	}
	if c.downloads[7] != 2 {
		t.Errorf("block 7 downloaded %d times, want once to settle and once to search", c.downloads[7])
	}
}

// TestSearchRPAPrefixesChainMoved checks that a run whose blocks leave the
// chain while it is searched blames no one: a reorg after the run's hashes
// were read still has every request name the same blocks, and a check that
// finds the run gone before a liar is blamed searches the run again, which
// then blames the liar.
func TestSearchRPAPrefixesChainMoved(t *testing.T) {
	c := newRPATestChain(20)
	target := c.inputsAt(13)[0]
	c.afterHashes = func() { c.reorg(12) }
	found, reached, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19)
	if err != nil || reached != 19 || len(c.banned) != 0 {
		t.Fatalf("a reorg after the hashes were read: reached %d, banned %v, %v",
			reached, c.banned, err)
	}
	if len(found) == 0 || found[0].Height != 13 {
		t.Fatalf("found %+v, want the block the run named", found)
	}

	c = newRPATestChain(20)
	target = c.inputsAt(7)[0]
	c.peers["liar"] = &rpaTestPeer{edit: func(height int32, filter []byte) []byte {
		if height == 7 {
			return []byte{0x00, 0x00, 0x00, 0x00}
		}
		return filter
	}}
	c.offChain = 1
	found, _, err = c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19)
	if err != nil || len(found) == 0 || found[0].Height != 7 {
		t.Fatalf("found %+v, %v", found, err)
	}
	if !slices.Equal(c.banned, []string{"liar"}) {
		t.Errorf("banned %v, want the liar once the chain held", c.banned)
	}

	// A chain that keeps moving ends the search, blaming no one.
	liar := c.peers["liar"]
	c = newRPATestChain(20)
	c.peers["liar"] = liar
	c.offChain = rpaChainMovedTries + 1
	if _, reached, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19); !errors.Is(err, errRPAChainMoved) ||
		reached != -1 || len(c.banned) != 0 {

		t.Errorf("a chain that keeps moving: reached %d, banned %v, %v", reached, c.banned, err)
	}

	// Hashes read across a reorg are read again.
	c = newRPATestChain(20)
	moved := &rpaMovedOnce{rpaTestChain: c}
	if reached, err := searchRPAPrefixes(moved, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19,
		func(RPAMatch) bool { return true }, nil, nil); err != nil || reached != 19 || moved.reads != 2 {
		t.Errorf("hashes read across a reorg: reached %d after %d reads, %v", reached, moved.reads, err)
	}

	// Headers that don't follow each other are not one chain.
	headers := []wire.BlockHeader{c.blocks[0].MsgBlock().Header, c.blocks[2].MsgBlock().Header}
	if _, err := linkedRPAHashes(headers); !errors.Is(err, errRPAChainMoved) {
		t.Errorf("headers that don't follow each other: %v", err)
	}
	headers[1] = c.blocks[1].MsgBlock().Header
	if hashes, err := linkedRPAHashes(headers); err != nil || hashes[1] != *c.blocks[1].Hash() {
		t.Errorf("headers that follow each other: %v", err)
	}
}

// rpaMovedOnce is a chain whose first read of a run's hashes crosses a reorg.
type rpaMovedOnce struct {
	*rpaTestChain
	reads int
}

func (s *rpaMovedOnce) runHashes(start, stop int32) ([]chainhash.Hash, error) {
	s.reads++
	if s.reads == 1 {
		return nil, errRPAChainMoved
	}
	return s.rpaTestChain.runHashes(start, stop)
}

// TestSearchRPAPrefixesWrongFilters checks the peers that agree on wrong
// filters: one that matches a block it shouldn't is shown wrong by the block,
// as is one that doesn't decode, which is checked as a match; one whose
// filter bytes don't have the agreed hash is dropped for another; and with
// no peer that answers there are none.
func TestSearchRPAPrefixesWrongFilters(t *testing.T) {
	const fake = 0xabcd
	for name, edit := range map[string]func(filter []byte) []byte{
		"a value its block lacks": func(filter []byte) []byte {
			values, _ := builder.DecodeRPAFilter(filter)
			values = append(values, fake)
			slices.Sort(values)
			return mustEncodeRPAFilter(t, slices.Compact(values))
		},
		"a filter that doesn't decode": func([]byte) []byte { return []byte{0xff} },
	} {
		c := newRPATestChain(20)
		for _, p := range c.peers {
			p.edit = func(height int32, filter []byte) []byte {
				if height != 5 {
					return filter
				}
				return edit(filter)
			}
		}
		_, reached, err := c.search(t, []RPAPrefix{{Value: fake, Bits: 16}}, 0, 19)
		slices.Sort(c.banned)
		if !errors.Is(err, ErrRPAFilterMismatch) || reached != 4 ||
			!slices.Equal(c.banned, []string{"honest", "honest2"}) {

			t.Errorf("%s: reached %d, banned %v, %v", name, reached, c.banned, err)
		}
	}

	// Filters whose bytes don't have the hashes the peer gave: the peer
	// is dropped and the filters are taken from another. The peer to ask
	// is picked at random, so the search runs until the liar was asked.
	checked := false
	for run := 0; run < 64 && !checked; run++ {
		c := newRPATestChain(20)
		c.peers["switcher"] = &rpaTestPeer{}
		target := c.inputsAt(10)[0]
		switcher := &rpaSwitchSource{rpaTestChain: c, peer: "switcher"}
		var found []RPAMatch
		_, err := searchRPAPrefixes(switcher, []RPAPrefix{{Value: target, Bits: 16}}, 0, 19,
			func(m RPAMatch) bool { found = append(found, m); return true }, nil, nil)
		if err != nil || len(found) == 0 || found[0].Height != 10 {
			t.Fatalf("found %+v, %v", found, err)
		}
		if switcher.asked == 0 {
			continue
		}
		checked = true
		if !slices.Equal(c.banned, []string{"switcher"}) {
			t.Errorf("banned %v, want the peer whose filters don't have its hashes", c.banned)
		}
	}
	if !checked {
		t.Error("the peer whose filters don't have its hashes was never asked")
	}

	// No peer answers.
	c := newRPATestChain(5)
	for _, p := range c.peers {
		p.silent = true
	}
	if _, _, err := c.search(t, []RPAPrefix{{Value: 1, Bits: 16}}, 0, 4, RPAMinPeers(1)); !errors.Is(err, ErrRPAFewPeers) {
		t.Errorf("without peers: %v", err)
	}
}

// TestSearchRPAPrefixesErrorHeights checks the height a search that ends with
// an error returns, from which it resumes one higher: below the block that
// couldn't be downloaded, below the run without peers, and below the run it
// was at when cancelled.
func TestSearchRPAPrefixesErrorHeights(t *testing.T) {
	defer func(batch int32) { rpaFilterBatch = batch }(rpaFilterBatch)
	rpaFilterBatch = 10

	c := newRPATestChain(30)
	target := c.inputsAt(13)[0]
	c.failBlock = 13
	if _, reached, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 29); err == nil || reached != 12 {
		t.Errorf("a block that can't be downloaded: reached %d, %v", reached, err)
	}

	c = newRPATestChain(30)
	c.peers["honest2"].edit = nil
	calls := 0
	src := &rpaQuietAfter{rpaTestChain: c, runs: 2, calls: &calls}
	if reached, err := searchRPAPrefixes(src, []RPAPrefix{{Value: 1, Bits: 16}}, 0, 29,
		func(RPAMatch) bool { return true }, nil, nil); !errors.Is(err, ErrRPAFewPeers) || reached != 19 {
		t.Errorf("a run without peers: reached %d, %v", reached, err)
	}

	quit := make(chan struct{})
	close(quit)
	if reached, err := searchRPAPrefixes(newRPATestChain(30), []RPAPrefix{{Value: 1, Bits: 16}},
		0, 29, func(RPAMatch) bool { return true }, nil, quit); !errors.Is(err, ErrSearchCancelled) || reached != -1 {
		t.Errorf("cancelled: reached %d, %v", reached, err)
	}
}

// rpaQuietAfter is a chain whose peers stop giving filter hashes after runs
// runs.
type rpaQuietAfter struct {
	*rpaTestChain
	runs  int
	calls *int
}

func (s *rpaQuietAfter) filterHashes(start int32, hashes []chainhash.Hash, minPeers int,
	quit <-chan struct{}) (map[string]*wire.MsgCFHeaders, error) {

	*s.calls++
	if *s.calls > s.runs {
		return nil, nil
	}
	return s.rpaTestChain.filterHashes(start, hashes, minPeers, quit)
}

// rpaSwitchSource serves, for one peer, filters other than those whose hashes
// it gave.
type rpaSwitchSource struct {
	*rpaTestChain
	peer  string
	asked int
}

func (s *rpaSwitchSource) filters(peer string, start int32, hashes []chainhash.Hash,
	quit <-chan struct{}) (map[chainhash.Hash][]byte, error) {

	got, err := s.rpaTestChain.filters(peer, start, hashes, quit)
	if peer == s.peer {
		s.asked++
		got[hashes[len(hashes)-1]] = []byte{0x00}
	}
	return got, err
}

// rpaAsk is an ask of a chainRPASource that answers from a script per peer.
type rpaAsk struct {
	mtx     sync.Mutex
	asked   map[string]int
	answers func(peer string, request wire.Message) []wire.Message

	// slow holds peers that answer only once the ask is ended.
	slow map[string]bool
}

func (a *rpaAsk) ask(peer string, request wire.Message, answers func(wire.Message) bool,
	_ replyWait, quit <-chan struct{}) (wire.Message, error) {

	a.mtx.Lock()
	a.asked[peer]++
	a.mtx.Unlock()
	if a.slow[peer] {
		<-quit
		return nil, ErrShuttingDown
	}
	for _, msg := range a.answers(peer, request) {
		if answers(msg) {
			return msg, nil
		}
	}
	return nil, errNoAnswer
}

// TestChainRPASource checks what the source that asks peers takes from them:
// cfilter messages only for the blocks of the run, each for its own block in
// whatever order they come, a late one of an earlier run left out; filter
// hashes from the peers that serve them; from a peer that serves the filters
// and no filter hashes, the hashes of its filters, which it is asked for
// straight away in the runs after, and kept to be handed over without asking
// again; a peer that gives neither twice left out after that, and a slow one
// not once enough peers answered.
func TestChainRPASource(t *testing.T) {
	c := newRPATestChain(20)
	run := make([]chainhash.Hash, 5)
	for i := range run {
		run[i] = *c.blocks[10+i].Hash()
	}
	stale := wire.NewMsgCFilter(wire.GCSFilterInputPrefix, c.blocks[3].Hash(), []byte{1})
	a := &rpaAsk{asked: make(map[string]int), slow: map[string]bool{"slow": true}}
	cfheaders := make(map[string]int)
	a.answers = func(peer string, request wire.Message) []wire.Message {
		switch req := request.(type) {
		case *wire.MsgGetCFilters:
			if peer == "old" {
				return nil
			}
			// A peer's messages can arrive out of order: these come
			// last block first.
			msgs := []wire.Message{stale, wire.NewMsgCFilter(wire.GCSFilterRegular, &run[0], []byte{2})}
			for i := len(run) - 1; i >= 0; i-- {
				msgs = append(msgs, wire.NewMsgCFilter(wire.GCSFilterInputPrefix, &run[i], []byte{byte(i)}))
			}
			return msgs
		case *wire.MsgGetCFHeaders:
			a.mtx.Lock()
			cfheaders[peer]++
			a.mtx.Unlock()
			if peer == "old" || peer == "filters" {
				return nil
			}
			msg := &wire.MsgCFHeaders{FilterType: wire.GCSFilterInputPrefix, StopHash: req.StopHash}
			for i := range run {
				filterHash := builder.GetRPAFilterHash([]byte{byte(i)})
				msg.FilterHashes = append(msg.FilterHashes, &filterHash)
			}
			return []wire.Message{&wire.MsgCFHeaders{FilterType: wire.GCSFilterRegular,
				StopHash: req.StopHash}, msg}
		}
		return nil
	}
	src := &chainRPASource{ask: a.ask,
		peers:  func() []string { return []string{"a", "b", "filters", "old", "slow"} },
		missed: make(map[string]int), silent: make(map[string]time.Time)}

	got, err := src.filters("a", 10, run, nil)
	if err != nil || len(got) != len(run) {
		t.Fatalf("filters %v, %v", got, err)
	}
	if _, ok := got[*c.blocks[3].Hash()]; ok {
		t.Error("a filter of a block outside the run was taken")
	}
	for i, hash := range run {
		if got[hash][0] != byte(i) {
			t.Errorf("filter of block %d is %x", i, got[hash])
		}
	}

	for round := range 3 {
		var answers map[string]*wire.MsgCFHeaders
		done := make(chan struct{})
		go func() {
			defer close(done)
			answers, err = src.filterHashes(10, run, 2, nil)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the filter hashes waited for the slow peer")
		}
		if err != nil || len(answers) != 3 || answers["a"] == nil || answers["b"] == nil ||
			answers["filters"] == nil {

			t.Fatalf("filter hashes from %v, %v", answers, err)
		}
		for _, msg := range answers {
			if msg.FilterType != wire.GCSFilterInputPrefix || msg.StopHash != run[4] {
				t.Fatal("another filter type's headers were taken")
			}
		}
		// The hashes of the filters of the peer that serves no filter
		// hashes are the ones the others give.
		for i := range run {
			if *answers["filters"].FilterHashes[i] != *answers["a"].FilterHashes[i] {
				t.Errorf("round %d: hash %d from the filters is %v, the peers give %v", round, i,
					answers["filters"].FilterHashes[i], answers["a"].FilterHashes[i])
			}
		}
		// Its filters are handed over without asking for them again.
		before := a.asked["filters"]
		kept, err := src.filters("filters", 10, run, nil)
		if err != nil || len(kept) != len(run) || a.asked["filters"] != before {
			t.Errorf("round %d: the filters given for the hashes were asked for again "+
				"(%d asks, then %d): %v, %v", round, before, a.asked["filters"], kept, err)
		}
	}
	if cfheaders["filters"] != 1 {
		t.Errorf("a peer that serves filters and no filter hashes was asked for "+
			"them %d times, want 1", cfheaders["filters"])
	}
	// Asked for filter hashes and then for filters in the first two rounds,
	// and not at all after.
	if a.asked["old"] != 4 {
		t.Errorf("a peer that gives neither filter hashes nor filters was asked %d times, "+
			"want 4", a.asked["old"])
	}
	if a.asked["slow"] != 3 {
		t.Errorf("a slow peer was asked %d times, want 3", a.asked["slow"])
	}
}

// TestSearchRPAPrefixesBitmap checks a block whose filter is coded as a
// bitmap, as one with RPAFilterBitmapFrom values or more is: its inputs are
// found by a full value and by a short prefix, and a peer that leaves a value
// out of the bitmap is shown wrong by the block.
func TestSearchRPAPrefixesBitmap(t *testing.T) {
	c := newRPATestChain(3)
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
		[]byte{3, 0, 0xbb}))
	coinbase.AddTxOut(wire.NewTxOut(5000, []byte{0x51}, wire.TokenData{}))
	msg := wire.NewMsgBlock(&wire.BlockHeader{Version: 4, PrevBlock: *c.blocks[2].Hash(),
		Nonce: 3, Bits: 0xbb})
	msg.Transactions = []*wire.MsgTx{coinbase}
	for i := 0; i < 900; i++ {
		tx := wire.NewMsgTx(2)
		for j := 0; j < 30; j++ {
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{byte(i), byte(i >> 8), 0xbb}, uint32(j)), nil))
		}
		tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}, wire.TokenData{}))
		msg.Transactions = append(msg.Transactions, tx)
	}
	big := bchutil.NewBlock(msg)
	big.SetHeight(3)
	c.blocks = append(c.blocks, big)
	c.known[*big.Hash()] = big

	filter := builder.BuildRPAFilter(msg)
	values, err := builder.DecodeRPAFilter(filter)
	if err != nil || len(values) < builder.RPAFilterBitmapFrom || filter[3] != builder.RPAFilterBitmap {
		t.Fatalf("the block's filter of %d values is not a bitmap: %v", len(values), err)
	}

	target := c.inputsAt(3)[100]
	found, reached, err := c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 3)
	if err != nil || reached != 3 || len(found) != 1 || found[0].Height != 3 {
		t.Fatalf("a full value: reached %d, found %+v, %v", reached, found, err)
	}
	if !slices.ContainsFunc(found[0].Inputs, func(in RPAInput) bool { return in.Value == target }) {
		t.Errorf("the input with the value isn't among %d", len(found[0].Inputs))
	}
	found, _, err = c.search(t, []RPAPrefix{{Value: target >> 12, Bits: 4}}, 3, 3)
	if err != nil || len(found) != 1 {
		t.Fatalf("a 4-bit prefix: found %d blocks, %v", len(found), err)
	}

	c.peers["liar"] = &rpaTestPeer{edit: func(height int32, filter []byte) []byte {
		if height != 3 {
			return filter
		}
		values, _ := builder.DecodeRPAFilter(filter)
		return mustEncodeRPAFilter(t, slices.DeleteFunc(values, func(v uint16) bool { return v == target }))
	}}
	found, _, err = c.search(t, []RPAPrefix{{Value: target, Bits: 16}}, 0, 3)
	if err != nil || len(found) != 1 || !slices.Equal(c.banned, []string{"liar"}) {
		t.Fatalf("a liar: found %d, banned %v, %v", len(found), c.banned, err)
	}
}
