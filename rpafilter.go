package neutrino

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/neutrino/banman"
)

// A wallet on a reusable payment address is paid by a transaction one of
// whose first 30 inputs the sender ground until the first bits of its double
// SHA-256 equal bits of the wallet's scan key, its prefix.  The input prefix
// filter (filter type 2) of a block holds the first 16 bits of that hash for
// each such input of the block, so a wallet finds the blocks that may pay it
// by matching its prefix against the filters, which every peer serves alike,
// and downloads only those.  No request names the prefix.
//
// The filters are taken in block mode only, a run of blocks at a time.  The
// hashes of the run's blocks are read once, as the ancestors of its last
// block, and every request names them, so a reorg while the run is searched
// can't mix two chains.  The peers that serve type 2 give the hashes of
// their filters: from cfheaders, or, from a peer that serves type 2 filters
// and no type 2 filter headers, as a node that builds each filter when asked
// and keeps nothing for it does, as the double SHA-256 of each of its
// filters, which is how BIP 157 defines the filter hash.  Where they
// disagree, the block is downloaded, its filter is
// built from it, and the peers that gave another hash are wrong.  The filters
// are then fetched from one peer and checked against those hashes.  A block
// whose filter matches is downloaded, its filter is built from it and
// compared with the one served, which shows the peers wrong if they differ,
// and its inputs with the prefix are handed to the caller.  Before a peer is
// blamed, the run's last block is checked to still be in our chain; if it
// isn't, the run is searched again.
//
// A peer that agrees with the others can still leave a value out of every
// filter, which only a peer that disagrees shows.  So a run needs filter
// hashes from at least two peers by default, and each match says how many
// agreed.

// RPAPrefix is a prefix of the first bits of an input's value: Value holds
// the first Bits bits, 1 to 16, of the 16-bit value.
type RPAPrefix struct {
	Value uint16
	Bits  uint8
}

// RPAInput is an input whose value has one of the prefixes searched for: the
// index of its transaction in the block, its own index, and its value.
type RPAInput struct {
	TxIndex int
	Index   int
	Value   uint16
}

// RPAMatch is a block with inputs whose values have one of the prefixes
// searched for.  Peers is how many peers agreed on the filters of the run of
// blocks it is in.
type RPAMatch struct {
	Height int32
	Block  *bchutil.Block
	Inputs []RPAInput
	Peers  int
}

var (
	// ErrNoRPAFilterPeers is returned when no peer gives the input prefix
	// filters of a run of blocks that the blocks don't show wrong.
	ErrNoRPAFilterPeers = errors.New("no peer serves the input prefix " +
		"filters of the blocks")

	// ErrRPAFewPeers is returned when fewer peers than the search needs
	// give the filter hashes of a run of blocks.
	ErrRPAFewPeers = errors.New("too few peers serve the input prefix " +
		"filters of the blocks")

	// ErrRPAFilterMismatch is returned when the input prefix filter every
	// peer agreed on is not the one its block gives.
	ErrRPAFilterMismatch = errors.New("the input prefix filter the peers " +
		"serve is not the one its block gives")

	// ErrRPAPrefix is returned for a prefix of no bits, of more than 16, or
	// with a bit set past its length.
	ErrRPAPrefix = errors.New("an input prefix is 1 to 16 bits")

	// ErrRPARange is returned for a range of heights that is not in our
	// chain: one that starts below zero, ends before it starts, or ends
	// above our best block.
	ErrRPARange = errors.New("the heights to search are not in the chain")

	// errRPAChainMoved is returned when the blocks of a run left our chain
	// while it was searched, so the run is searched again.
	errRPAChainMoved = errors.New("the blocks searched left the chain")
)

// rpaFilterBatch is how many blocks' filters are asked for at once: as many
// as one getcfilters can ask for.
var rpaFilterBatch int32 = wire.MaxGetCFiltersReqRange

// rpaFilterWait is how long a peer has to answer for the filters or filter
// hashes of a run of blocks: 20 seconds of silence, extended while its
// connection gives bytes, up to 5 minutes, for slow links such as Tor and
// I2P.
var rpaFilterWait = replyWait{quiet: 20 * time.Second, most: 5 * time.Minute}

const (
	// DefaultRPAMinPeers is how many peers have to give the filter
	// hashes of a run of blocks by default.
	DefaultRPAMinPeers = 2

	// rpaHashesGrace is how long the filter hashes of a run are waited
	// for from the other peers once enough peers have given theirs.
	rpaHashesGrace = 2 * time.Second

	// rpaSilentFor is how long a peer that didn't give the filter hashes
	// of two runs in a row is left out: one that doesn't serve type 2,
	// as an older node, one that prunes, or one still building its index.
	rpaSilentFor = 10 * time.Minute

	// rpaBlockFetches is how many matching blocks are downloaded at once.
	rpaBlockFetches = 4

	// rpaChainMovedTries is how many times in a row a run is searched
	// again because its blocks left the chain before the search gives up.
	rpaChainMovedTries = 3
)

// RPASearchOption is an option of SearchRPAPrefixes.
type RPASearchOption func(*rpaSearchOptions)

// rpaSearchOptions holds the options of a search.
type rpaSearchOptions struct {
	minPeers int
}

// RPAMinPeers sets how many peers have to give the filter hashes of each run
// of blocks, DefaultRPAMinPeers when not set.  One is enough for a wallet
// that trusts its own node.
func RPAMinPeers(n int) RPASearchOption {
	return func(o *rpaSearchOptions) {
		o.minPeers = max(n, 1)
	}
}

// rpaSource is what a search reads: the blocks and filters of the peers that
// serve them.  Each returns ErrShuttingDown, or ErrSearchCancelled, when
// quit closes.
type rpaSource interface {
	// tip returns the height of our best block.
	tip() (int32, error)

	// runHashes returns the hashes of the blocks from start to stop of our
	// chain, read together, so that each is the parent of the next.  It
	// returns errRPAChainMoved when they aren't.
	runHashes(start, stop int32) ([]chainhash.Hash, error)

	// onChain returns whether the block is still at height in our chain.
	onChain(hash chainhash.Hash, height int32) bool

	// filterHashes asks the peers that serve type 2 for the filter hashes
	// of the blocks of a run, hashes, from start, and returns the answers
	// by peer.  It waits for every peer it asks, or, once minPeers have
	// answered, a short grace.  A peer that doesn't answer is left out.
	filterHashes(start int32, hashes []chainhash.Hash, minPeers int,
		quit <-chan struct{}) (map[string]*wire.MsgCFHeaders, error)

	// filters asks a peer for the filters of the given blocks, from start,
	// and returns them by block hash.  Only a filter for one of the
	// blocks counts.  It returns nil when the peer doesn't give them all.
	filters(peer string, start int32, hashes []chainhash.Hash,
		quit <-chan struct{}) (map[chainhash.Hash][]byte, error)

	// block downloads a block.
	block(hash chainhash.Hash, quit <-chan struct{}) (*bchutil.Block, error)

	// bad drops a peer shown to serve a wrong filter.
	bad(peer string)
}

// checkRPAPrefixes checks that each prefix has 1 to 16 bits and none set past
// its length.
func checkRPAPrefixes(prefixes []RPAPrefix) error {
	for _, p := range prefixes {
		if p.Bits == 0 || p.Bits > 16 || (p.Bits < 16 && p.Value>>p.Bits != 0) {
			return fmt.Errorf("%w: %x/%d", ErrRPAPrefix, p.Value, p.Bits)
		}
	}
	return nil
}

// rpaPrefixesMatch reports whether sorted filter values hold one with any of
// the prefixes.
func rpaPrefixesMatch(values []uint16, prefixes []RPAPrefix) bool {
	for _, p := range prefixes {
		if builder.RPAFilterMatch(values, p.Value, p.Bits) {
			return true
		}
	}
	return false
}

// rpaInputsOf returns the inputs of a block whose values have any of the
// prefixes: of the first 30 inputs of each transaction but the coinbase.
func rpaInputsOf(block *wire.MsgBlock, prefixes []RPAPrefix) []RPAInput {
	var inputs []RPAInput
	for i, tx := range block.Transactions {
		if i == 0 {
			continue
		}
		for j, txIn := range tx.TxIn {
			if j == builder.RPAFilterInputs {
				break
			}
			v := builder.RPAInputValue(txIn)
			if rpaPrefixesMatch([]uint16{v}, prefixes) {
				inputs = append(inputs, RPAInput{TxIndex: i, Index: j, Value: v})
			}
		}
	}
	return inputs
}

// rpaRun is a run of blocks whose filters the peers agree on.
type rpaRun struct {
	from, to int32
	hashes   []chainhash.Hash
	filters  [][]byte
	peers    []string
}

// blameRPAPeers drops peers shown wrong by a block of a run, unless the run's
// last block left our chain meanwhile, when it returns errRPAChainMoved and
// blames no one.
func blameRPAPeers(src rpaSource, run *rpaRun, peers []string) error {
	if len(peers) == 0 {
		return nil
	}
	if !src.onChain(run.hashes[len(run.hashes)-1], run.to) {
		return errRPAChainMoved
	}
	for _, peer := range peers {
		src.bad(peer)
	}
	return nil
}

// agreeRPAFilterHashes returns the peers that agree on the filter hashes of
// the blocks of a run, which it sets.  Where peers disagree on a block, the
// block is downloaded and the peers whose hash for it is not the one it gives
// are dropped.
func agreeRPAFilterHashes(src rpaSource, run *rpaRun, minPeers int,
	quit <-chan struct{}) ([]chainhash.Hash, error) {

	count := len(run.hashes)
	stopHash := run.hashes[count-1]
	replies, err := src.filterHashes(run.from, run.hashes, minPeers, quit)
	if err != nil {
		return nil, err
	}
	answers := make(map[string][]chainhash.Hash)
	var malformed []string
	for peer, msg := range replies {
		if msg.FilterType != wire.GCSFilterInputPrefix || msg.StopHash != stopHash ||
			len(msg.FilterHashes) != count {

			malformed = append(malformed, peer)
			continue
		}
		hashes := make([]chainhash.Hash, count)
		for i, h := range msg.FilterHashes {
			hashes[i] = *h
		}
		answers[peer] = hashes
	}
	if err := blameRPAPeers(src, run, malformed); err != nil {
		return nil, err
	}
	if len(answers) < minPeers {
		return nil, fmt.Errorf("%w: %d of the %d needed gave the filter hashes "+
			"of blocks %d to %d", ErrRPAFewPeers, len(answers), minPeers,
			run.from, run.to)
	}

	for len(answers) > 0 {
		var peers []string
		for peer := range answers {
			peers = append(peers, peer)
		}
		slices.Sort(peers)
		first := answers[peers[0]]

		// The first block whose filter hash not every peer agrees on.
		at := -1
		for i := 0; i < count && at < 0; i++ {
			for _, peer := range peers[1:] {
				if answers[peer][i] != first[i] {
					at = i
					break
				}
			}
		}
		if at < 0 {
			run.peers = peers
			return first, nil
		}

		block, err := src.block(run.hashes[at], quit)
		if err != nil {
			return nil, err
		}
		want := builder.GetRPAFilterHash(builder.BuildRPAFilter(block.MsgBlock()))
		var wrong []string
		for _, peer := range peers {
			if answers[peer][at] != want {
				log.Warnf("Peer %v serves a wrong input prefix filter "+
					"hash for block %v", peer, run.hashes[at])
				wrong = append(wrong, peer)
				delete(answers, peer)
			}
		}
		if err := blameRPAPeers(src, run, wrong); err != nil {
			return nil, err
		}
	}
	return nil, ErrNoRPAFilterPeers
}

// fetchRPAFilters fetches the filters of the blocks of a run from one of its
// peers, in random order, that gives them all with the agreed hashes, and
// sets them.  A peer that gives others is dropped.
func fetchRPAFilters(src rpaSource, run *rpaRun, hashes []chainhash.Hash,
	quit <-chan struct{}) error {

	order := slices.Clone(run.peers)
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for _, peer := range order {
		byBlock, err := src.filters(peer, run.from, run.hashes, quit)
		if err != nil {
			return err
		}
		if byBlock == nil {
			continue
		}
		filters := make([][]byte, len(hashes))
		ok := true
		for i := range hashes {
			data, found := byBlock[run.hashes[i]]
			if !found || builder.GetRPAFilterHash(data) != hashes[i] {
				ok = false
				break
			}
			filters[i] = data
		}
		if !ok {
			log.Warnf("Peer %v serves an input prefix filter that is not "+
				"the one whose hash the peers agree on", peer)
			if err := blameRPAPeers(src, run, []string{peer}); err != nil {
				return err
			}
			continue
		}
		run.filters = filters
		return nil
	}
	return ErrNoRPAFilterPeers
}

// prepareRPARun reads the hashes of the blocks from from to to, has the peers
// agree on their filters and fetches them.
func prepareRPARun(src rpaSource, from, to int32, minPeers int,
	quit <-chan struct{}) (*rpaRun, error) {

	hashes, err := src.runHashes(from, to)
	if err != nil {
		return nil, err
	}
	run := &rpaRun{from: from, to: to, hashes: hashes}
	filterHashes, err := agreeRPAFilterHashes(src, run, minPeers, quit)
	if err != nil {
		return nil, err
	}
	if err := fetchRPAFilters(src, run, filterHashes, quit); err != nil {
		return nil, err
	}
	return run, nil
}

// rpaRunMatches downloads the blocks of a run whose filters match, a few at a
// time, checks each against its filter, and returns the matches with inputs
// that have a prefix, in order.  A filter that doesn't decode is checked
// against its block like one that matches.
func rpaRunMatches(src rpaSource, run *rpaRun, prefixes []RPAPrefix,
	quit <-chan struct{}) ([]RPAMatch, int32, error) {

	var heights []int32
	for i, filter := range run.filters {
		values, err := builder.DecodeRPAFilter(filter)
		if err == nil && !rpaPrefixesMatch(values, prefixes) {
			continue
		}
		heights = append(heights, run.from+int32(i))
	}

	blocks := make([]*bchutil.Block, len(heights))
	errs := make([]error, len(heights))
	var wg sync.WaitGroup
	slots := make(chan struct{}, rpaBlockFetches)
	for i, height := range heights {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			blocks[i], errs[i] = src.block(run.hashes[height-run.from], quit)
		}()
	}
	wg.Wait()

	var matches []RPAMatch
	for i, height := range heights {
		if errs[i] != nil {
			return matches, height - 1, errs[i]
		}
		filter := run.filters[height-run.from]
		if !bytes.Equal(builder.BuildRPAFilter(blocks[i].MsgBlock()), filter) {
			if err := blameRPAPeers(src, run, run.peers); err != nil {
				return matches, height - 1, err
			}
			return matches, height - 1, fmt.Errorf("%w: block %v",
				ErrRPAFilterMismatch, run.hashes[height-run.from])
		}
		inputs := rpaInputsOf(blocks[i].MsgBlock(), prefixes)
		if len(inputs) == 0 {
			continue
		}
		matches = append(matches, RPAMatch{
			Height: height, Block: blocks[i], Inputs: inputs,
			Peers: len(run.peers),
		})
	}
	return matches, run.to, nil
}

// rpaPrepared is a run prepared ahead, or the error that ended it.
type rpaPrepared struct {
	run *rpaRun
	err error
}

// searchRPAPrefixes searches the blocks from start to end, both included, for
// inputs with any of the prefixes, and hands each block that has some to
// found, in order, until found returns false.  After each run of blocks it
// calls progress, when it is set, with the last height of the run and the
// number of peers that agreed on its filters.  The filters of the next run
// are fetched while the blocks of one are.  It returns the last height
// searched: a search that ends with an error resumes from the height after
// it.
func searchRPAPrefixes(src rpaSource, prefixes []RPAPrefix, start, end int32,
	found func(RPAMatch) bool, progress func(height int32, peers int),
	quit <-chan struct{}, options ...RPASearchOption) (int32, error) {

	opts := rpaSearchOptions{minPeers: DefaultRPAMinPeers}
	for _, option := range options {
		option(&opts)
	}
	if err := checkRPAPrefixes(prefixes); err != nil {
		return start - 1, err
	}
	tip, err := src.tip()
	if err != nil {
		return start - 1, err
	}
	if start < 0 || end < start || end > tip {
		return start - 1, fmt.Errorf("%w: %d to %d, with the best block at %d",
			ErrRPARange, start, end, tip)
	}

	// A run prepared ahead ends when the search does.
	done := make(chan struct{})
	defer close(done)
	runQuit := make(chan struct{})
	go func() {
		select {
		case <-quit:
		case <-done:
		}
		close(runQuit)
	}()
	prepare := func(from int32) <-chan rpaPrepared {
		ready := make(chan rpaPrepared, 1)
		go func() {
			to := min(from+rpaFilterBatch-1, end)
			run, err := prepareRPARun(src, from, to, opts.minPeers, runQuit)
			ready <- rpaPrepared{run: run, err: err}
		}()
		return ready
	}

	moved := 0
	next := prepare(start)
	for from := start; from <= end; {
		var prepared rpaPrepared
		select {
		case prepared = <-next:
		case <-quit:
			return from - 1, ErrSearchCancelled
		}
		next = nil
		if errors.Is(prepared.err, errRPAChainMoved) && moved < rpaChainMovedTries {
			moved++
			next = prepare(from)
			continue
		}
		if prepared.err != nil {
			return from - 1, stoppedRPA(prepared.err, quit)
		}
		run := prepared.run
		if run.to < end {
			next = prepare(run.to + 1)
		}

		matches, reached, err := rpaRunMatches(src, run, prefixes, runQuit)
		for _, match := range matches {
			if !found(match) {
				return match.Height, nil
			}
		}
		if errors.Is(err, errRPAChainMoved) && moved < rpaChainMovedTries {
			moved++
			from = reached + 1
			next = prepare(from)
			continue
		}
		if err != nil {
			return reached, stoppedRPA(err, quit)
		}
		moved = 0
		if progress != nil {
			progress(run.to, len(run.peers))
		}
		from = run.to + 1
	}
	return end, nil
}

// stoppedRPA returns ErrSearchCancelled for an error that ended a search
// because quit closed.
func stoppedRPA(err error, quit <-chan struct{}) error {
	select {
	case <-quit:
		return ErrSearchCancelled
	default:
		return err
	}
}

// SearchRPAPrefixes searches the blocks of our chain from start to end, both
// included, for inputs whose values have any of the prefixes, as a wallet on
// a reusable payment address looks for its payments, and hands each block
// that has some to found, in order, until found returns false.  After each
// run of up to 1000 blocks it calls progress, when it is set, with the run's
// last height and the number of peers that agreed on its filters.  It
// returns the last height searched, so a search that ends with an error, or
// is cancelled by closing quit with ErrSearchCancelled, resumes from that
// height plus one.  The range is checked first: it must start at zero or
// above and end at or below our best block, after it starts.
//
// It reads the input prefix filters (filter type 2) of the peers that serve
// them and downloads only the blocks whose filters match, so no request
// names a prefix; a peer shown to serve a wrong filter is banned.  Each run
// needs the filter hashes of RPAMinPeers peers, two by default, and returns
// ErrRPAFewPeers with fewer.  The blocks downloaded are what a peer can
// learn from: see gcash/bchd's filter type 2 on making them unlinkable.
func (s *ChainService) SearchRPAPrefixes(prefixes []RPAPrefix, start, end int32,
	found func(RPAMatch) bool, progress func(height int32, peers int),
	quit <-chan struct{}, options ...RPASearchOption) (int32, error) {

	src := &chainRPASource{s: s, ask: s.askPeer, peers: s.rpaPeers,
		missed: make(map[string]int), silent: make(map[string]time.Time),
		filtersOnly: make(map[string]time.Time),
		fetched:     make(map[string]map[chainhash.Hash][]byte)}
	return searchRPAPrefixes(src, prefixes, start, end, found, progress, quit,
		options...)
}

// rpaPeers returns the addresses of the connected peers.
func (s *ChainService) rpaPeers() []string {
	var peers []string
	for _, sp := range s.Peers() {
		if sp.Connected() {
			peers = append(peers, sp.Addr())
		}
	}
	return peers
}

// chainRPASource reads blocks and filters from a ChainService's peers.  It
// remembers the peers that give neither filter hashes nor filters, which
// don't serve type 2, and leaves them out for a while, and the peers that
// give filters but no filter hashes, which it asks for their filters
// straight away for a while.
type chainRPASource struct {
	s   *ChainService
	ask func(peer string, request wire.Message, answers func(wire.Message) bool,
		wait replyWait, quit <-chan struct{}) (wire.Message, error)
	peers func() []string

	mtx    sync.Mutex
	missed map[string]int
	silent map[string]time.Time

	// filtersOnly holds the peers that serve type 2 filters but no type 2
	// filter headers, until when they are not asked for filter headers.
	filtersOnly map[string]time.Time

	// fetched holds the filters a peer gave in place of filter hashes,
	// until they are asked for, so that they are not fetched twice.
	fetched map[string]map[chainhash.Hash][]byte
}

func (c *chainRPASource) tip() (int32, error) {
	_, height, err := c.s.BlockHeaders.ChainTip()
	return int32(height), err
}

func (c *chainRPASource) runHashes(start, stop int32) ([]chainhash.Hash, error) {
	stopHeader, err := c.s.BlockHeaders.FetchHeaderByHeight(uint32(stop))
	if err != nil {
		return nil, err
	}
	stopHash := stopHeader.BlockHash()
	headers, first, err := c.s.BlockHeaders.FetchHeaderAncestors(uint32(stop-start), &stopHash)
	if err != nil || first != uint32(start) || len(headers) != int(stop-start+1) {
		return nil, fmt.Errorf("%w: %v", errRPAChainMoved, err)
	}
	hashes, err := linkedRPAHashes(headers)
	if err != nil || hashes[len(hashes)-1] != stopHash {
		return nil, errRPAChainMoved
	}
	return hashes, nil
}

// linkedRPAHashes returns the hashes of headers that each follow the one
// before, or errRPAChainMoved.
func linkedRPAHashes(headers []wire.BlockHeader) ([]chainhash.Hash, error) {
	hashes := make([]chainhash.Hash, len(headers))
	for i := range headers {
		hashes[i] = headers[i].BlockHash()
		if i > 0 && headers[i].PrevBlock != hashes[i-1] {
			return nil, errRPAChainMoved
		}
	}
	return hashes, nil
}

func (c *chainRPASource) onChain(hash chainhash.Hash, height int32) bool {
	header, err := c.s.BlockHeaders.FetchHeaderByHeight(uint32(height))
	return err == nil && header.BlockHash() == hash
}

func (c *chainRPASource) filterHashes(start int32, hashes []chainhash.Hash, minPeers int,
	quit <-chan struct{}) (map[string]*wire.MsgCFHeaders, error) {

	// Peers left out while they are known not to answer.
	c.mtx.Lock()
	now := time.Now()
	var asked []string
	for _, peer := range c.peers() {
		if until, ok := c.silent[peer]; ok && now.Before(until) {
			continue
		}
		asked = append(asked, peer)
	}
	c.mtx.Unlock()

	type answer struct {
		peer string
		msg  *wire.MsgCFHeaders
	}
	stopAsking := make(chan struct{})
	defer close(stopAsking)
	askQuit := make(chan struct{})
	go func() {
		select {
		case <-quit:
		case <-stopAsking:
		}
		close(askQuit)
	}()
	answers := make(chan answer, len(asked))
	for _, peer := range asked {
		go func() {
			answers <- answer{peer: peer, msg: c.peerFilterHashes(peer, start, hashes, askQuit)}
		}()
	}

	got := make(map[string]*wire.MsgCFHeaders)
	var silent []string
	var grace <-chan time.Time
	for heard := 0; heard < len(asked); {
		select {
		case a := <-answers:
			heard++
			if a.msg == nil {
				silent = append(silent, a.peer)
			} else {
				got[a.peer] = a.msg
			}
			if grace == nil && len(got) >= minPeers {
				grace = time.After(rpaHashesGrace)
			}
			continue
		case <-grace:
		case <-quit:
			return nil, ErrSearchCancelled
		}
		break
	}

	// A peer that didn't answer within its whole wait, twice in a row, is
	// left out for a while.  One still being waited for when the grace
	// ended is only slower than the others.
	c.mtx.Lock()
	defer c.mtx.Unlock()
	for peer := range got {
		delete(c.missed, peer)
	}
	for _, peer := range silent {
		c.missed[peer]++
		if c.missed[peer] >= 2 {
			log.Debugf("Peer %v gives no input prefix filter hashes or "+
				"filters, leaving it out for %v", peer, rpaSilentFor)
			c.silent[peer] = now.Add(rpaSilentFor)
			delete(c.missed, peer)
		}
	}
	return got, nil
}

// peerFilterHashes returns a peer's filter hashes of the blocks of a run, or
// nil.  A peer that gives no cfheaders for them is asked for the run's
// filters, and the double SHA-256 of each filter, the filter hash of BIP
// 157, stands in for its answer, in a message no one reads the previous
// filter header of: such a peer serves type 2 filters and keeps no type 2
// filter headers.  Its filters are kept for the run, and in the runs that
// follow, for a while, it is asked for its filters straight away.
func (c *chainRPASource) peerFilterHashes(peer string, start int32,
	hashes []chainhash.Hash, quit <-chan struct{}) *wire.MsgCFHeaders {

	stop := hashes[len(hashes)-1]
	c.mtx.Lock()
	until, filtersOnly := c.filtersOnly[peer]
	filtersOnly = filtersOnly && time.Now().Before(until)
	c.mtx.Unlock()

	if !filtersOnly {
		msg, err := c.ask(peer,
			wire.NewMsgGetCFHeaders(wire.GCSFilterInputPrefix, uint32(start), &stop),
			func(msg wire.Message) bool {
				headers, ok := msg.(*wire.MsgCFHeaders)
				return ok && headers.FilterType == wire.GCSFilterInputPrefix &&
					headers.StopHash == stop
			}, rpaFilterWait, quit,
		)
		if err == nil {
			return msg.(*wire.MsgCFHeaders)
		}
		if !errors.Is(err, errNoAnswer) {
			return nil
		}
	}

	byBlock, err := c.filters(peer, start, hashes, quit)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if err != nil || byBlock == nil {
		delete(c.filtersOnly, peer)
		return nil
	}
	msg := wire.NewMsgCFHeaders()
	msg.FilterType = wire.GCSFilterInputPrefix
	msg.StopHash = stop
	for _, hash := range hashes {
		filterHash := builder.GetRPAFilterHash(byBlock[hash])
		if err := msg.AddCFHash(&filterHash); err != nil {
			return nil
		}
	}
	if c.filtersOnly == nil {
		c.filtersOnly = make(map[string]time.Time)
	}
	if c.fetched == nil {
		c.fetched = make(map[string]map[chainhash.Hash][]byte)
	}
	if !filtersOnly {
		log.Debugf("Peer %v serves input prefix filters without their "+
			"filter hashes; taking the hashes of its filters", peer)
	}
	c.filtersOnly[peer] = time.Now().Add(rpaSilentFor)
	c.fetched[peer] = byBlock
	return msg
}

func (c *chainRPASource) filters(peer string, start int32, hashes []chainhash.Hash,
	quit <-chan struct{}) (map[chainhash.Hash][]byte, error) {

	// The filters a peer gave in place of filter hashes for this run.
	c.mtx.Lock()
	kept := c.fetched[peer]
	delete(c.fetched, peer)
	c.mtx.Unlock()
	if len(kept) == len(hashes) {
		all := true
		for _, hash := range hashes {
			if _, ok := kept[hash]; !ok {
				all = false
				break
			}
		}
		if all {
			return kept, nil
		}
	}

	// A peer's messages are handed to us each on its own goroutine, so
	// they can arrive out of order; one filter for each block of the run is
	// taken, and a late answer to an earlier request is not.
	want := make(map[chainhash.Hash]bool, len(hashes))
	for _, hash := range hashes {
		want[hash] = true
	}
	got := make(map[chainhash.Hash][]byte, len(hashes))
	stop := hashes[len(hashes)-1]
	_, err := c.ask(peer,
		wire.NewMsgGetCFilters(wire.GCSFilterInputPrefix, uint32(start), &stop),
		func(msg wire.Message) bool {
			filter, ok := msg.(*wire.MsgCFilter)
			if !ok || filter.FilterType != wire.GCSFilterInputPrefix ||
				!want[filter.BlockHash] {

				return false
			}
			if _, seen := got[filter.BlockHash]; !seen {
				got[filter.BlockHash] = filter.Data
			}
			return len(got) == len(hashes)
		}, rpaFilterWait, quit,
	)
	switch {
	case errors.Is(err, ErrShuttingDown):
		return nil, ErrSearchCancelled
	case err != nil:
		return nil, nil
	}
	return got, nil
}

func (c *chainRPASource) block(hash chainhash.Hash, quit <-chan struct{}) (*bchutil.Block, error) {
	return c.s.GetBlock(hash, QueryQuit(quit))
}

func (c *chainRPASource) bad(peer string) {
	if err := c.s.BanPeer(peer, banman.InvalidFilterHeader); err != nil {
		log.Errorf("Unable to ban peer %v: %v", peer, err)
	}
	if sp := c.s.PeerByAddr(peer); sp != nil {
		sp.Disconnect()
	}
}
