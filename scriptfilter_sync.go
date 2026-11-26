package neutrino

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"sort"
	"time"

	"github.com/aead/siphash"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/neutrino/banman"
	"github.com/kkdai/bstream"
)

// servedFilter is a filter a peer served for a block: the filter, and for a
// script filter the root of the block's entry tree that came in front of it.
type servedFilter struct {
	filter *gcs.Filter
	root   chainhash.Hash
}

// errNoAnswer is returned when a peer is gone or doesn't answer in time.  It
// says nothing of whether the peer serves the true filter: bchd ignores the
// requests for filters, proofs and leaves while it isn't current, and a
// getcfrange whose answer doesn't fit one message.
var errNoAnswer = errors.New("no answer from the peer")

// replyWait is how long askPeer waits for an answer: quiet after the request,
// and while the peer's connection keeps giving bytes, as it does while a large
// answer arrives over a slow link, quiet after the last one, but never longer
// than most after the request.
type replyWait struct {
	quiet time.Duration
	most  time.Duration
}

// left returns how much longer to wait at now for the answer to a request
// made at asked, from a peer whose connection last gave a byte at last, or
// zero or less once the wait is over.
func (w replyWait) left(asked, last, now time.Time) time.Duration {
	if last.Before(asked) {
		last = asked
	}
	end := last.Add(w.quiet)
	if most := asked.Add(w.most); end.After(most) {
		end = most
	}
	return end.Sub(now)
}

// askPeer sends a request to one peer and returns the first message from it
// that answers.  It returns errNoAnswer when the peer is gone or doesn't
// answer within wait, and ErrShuttingDown when quit closes first.
func (s *ChainService) askPeer(peer string, request wire.Message,
	answers func(wire.Message) bool, wait replyWait,
	quit <-chan struct{}) (wire.Message, error) {

	sp := s.PeerByAddr(peer)
	if sp == nil || !sp.Connected() {
		return nil, errNoAnswer
	}

	msgChan := make(chan spMsg)
	subQuit := make(chan struct{})
	subscription := spMsgSubscription{msgChan: msgChan, quitChan: subQuit}
	sp.subscribeRecvMsg(subscription)
	defer func() {
		sp.unsubscribeRecvMsgs(subscription)
		close(subQuit)
	}()

	sp.QueueMessage(request, nil)

	asked := time.Now()
	timer := time.NewTimer(wait.quiet)
	defer timer.Stop()
	for {
		select {
		case m := <-msgChan:
			if answers(m.msg) {
				return m.msg, nil
			}

		case <-timer.C:
			last := time.Unix(0, sp.lastRead.Load())
			left := wait.left(asked, last, time.Now())
			if left > 0 {
				timer.Reset(left)
				continue
			}
			log.Debugf("Peer %v didn't answer our %v in time", peer,
				request.Command())
			return nil, errNoAnswer

		case <-sp.quit:
			return nil, errNoAnswer

		case <-quit:
			return nil, ErrShuttingDown
		}
	}
}

// askAgain calls ask up to tries times, pausing between tries, for as long as
// it returns errNoAnswer.  A node that isn't current ignores a request, which
// a new block makes it for a moment, so one request that isn't answered says
// little.  It returns ErrShuttingDown when quit closes during a pause.
func askAgain[T any](tries int, pause time.Duration, quit <-chan struct{},
	ask func() (T, error)) (T, error) {

	for try := 1; ; try++ {
		answer, err := ask()
		if !errors.Is(err, errNoAnswer) || try >= tries {
			return answer, err
		}
		select {
		case <-time.After(pause):
		case <-quit:
			var none T
			return none, ErrShuttingDown
		}
	}
}

const (
	// scriptTreeBanScore is what bchd adds to the ban score it keeps for
	// a peer for each getcfrange and each getcfproof.
	scriptTreeBanScore = 1

	// scriptTreeScoreTick is how often a request that waits for the ban
	// score a peer keeps for us to decay looks at it again.
	scriptTreeScoreTick = time.Second

	// scriptTreeTries is how many times a peer is asked for one proof
	// before it counts as not answering, and scriptTreeRetryPause is the
	// pause between the tries.
	scriptTreeTries      = 2
	scriptTreeRetryPause = 5 * time.Second
)

// scriptTreeWait is how long a peer has to answer a getcfproof or getcfrange:
// 30 seconds of silence, which covers bchd reading a large block and its
// spend journal to build the block's entry tree and the round trips of slow
// links such as Tor and I2P, and up to 10 minutes while the answer, up to
// several megabytes for a range, keeps arriving.
var scriptTreeWait = replyWait{quiet: 30 * time.Second, most: 10 * time.Minute}

// takeBanScore counts add toward score, which mirrors the ban score a peer
// keeps for us, once that leaves it at maxMempoolBanScore or below, and until
// then waits for the score to decay.  It returns errNoAnswer when gone reports
// that the peer left, and ErrShuttingDown when quit closes, before it could.
func takeBanScore(score *banScoreMirror, add uint32, tick time.Duration,
	gone func() bool, quit <-chan struct{}) error {

	for {
		if gone() {
			return errNoAnswer
		}
		if score.tryTake(add, add, maxMempoolBanScore) {
			return nil
		}
		select {
		case <-time.After(tick):
		case <-quit:
			return ErrShuttingDown
		}
	}
}

// takeScriptTreeScore counts one getcfrange or getcfproof toward the ban
// score a peer keeps for us, and waits while one more would get us banned.
// Peers that disagree are each asked for a proof at every level of a block's
// entry tree, and one that makes up disagreements could otherwise have an
// honest peer ban us for the proofs we then ask it for.  It returns
// errNoAnswer when the peer is gone and ErrShuttingDown when quit closes.
func (s *ChainService) takeScriptTreeScore(peer string, quit <-chan struct{}) error {
	sp := s.PeerByAddr(peer)
	if sp == nil {
		return errNoAnswer
	}
	return takeBanScore(
		&sp.mempoolScore, scriptTreeBanScore, scriptTreeScoreTick,
		func() bool { return !sp.Connected() }, quit,
	)
}

// scriptTreeSource fetches the proofs and leaves of a block's entry tree from
// peers.  Both return errNoAnswer when the peer doesn't answer, and
// ErrShuttingDown when quit closes.
type scriptTreeSource interface {
	fetchScriptProof(peer string, blockHash chainhash.Hash, index uint32,
		quit <-chan struct{}) (*wire.MsgCFProof, error)

	fetchScriptRange(peer string, blockHash chainhash.Hash, bits uint16,
		prefix [32]byte, quit <-chan struct{}) (*wire.MsgCFRange, error)
}

// A compile-time check that a ChainService fetches entry trees from its
// peers.
var _ scriptTreeSource = (*ChainService)(nil)

// fetchScriptProof asks one peer for the cfproof of a leaf of a block's script
// filter entry tree, and asks once more when it doesn't answer.
func (s *ChainService) fetchScriptProof(peer string, blockHash chainhash.Hash,
	index uint32, quit <-chan struct{}) (*wire.MsgCFProof, error) {

	return askAgain(scriptTreeTries, scriptTreeRetryPause, quit,
		func() (*wire.MsgCFProof, error) {
			if err := s.takeScriptTreeScore(peer, quit); err != nil {
				return nil, err
			}
			msg, err := s.askPeer(
				peer, wire.NewMsgGetCFProof(wire.GCSFilterScripts, &blockHash, index),
				func(msg wire.Message) bool {
					proof, ok := msg.(*wire.MsgCFProof)
					return ok && proof.BlockHash == blockHash &&
						proof.LeafIndex == index
				}, scriptTreeWait, quit,
			)
			if err != nil {
				return nil, err
			}
			return msg.(*wire.MsgCFProof), nil
		},
	)
}

// fetchScriptRange asks one peer for the leaves of a block's script filter
// entry tree whose keys start with a prefix.  It asks once: bchd doesn't
// answer for a range too large for one message, which is then split.
func (s *ChainService) fetchScriptRange(peer string, blockHash chainhash.Hash,
	bits uint16, prefix [32]byte, quit <-chan struct{}) (*wire.MsgCFRange, error) {

	if err := s.takeScriptTreeScore(peer, quit); err != nil {
		return nil, err
	}

	// A cfrange doesn't repeat the prefix it answers.  We ask a peer for
	// one range at a time, so the next cfrange for the block is the
	// answer, which is then checked against the prefix.
	msg, err := s.askPeer(
		peer, wire.NewMsgGetCFRange(wire.GCSFilterScripts, &blockHash, bits, prefix),
		func(msg wire.Message) bool {
			leaves, ok := msg.(*wire.MsgCFRange)
			return ok && leaves.BlockHash == blockHash
		}, scriptTreeWait, quit,
	)
	if err != nil {
		return nil, err
	}
	return msg.(*wire.MsgCFRange), nil
}

// errScriptDisputeUnsettled is returned when the peers that announced
// different script filters for a block can't all be told apart: one that
// announced another than the filter the others back didn't answer.
var errScriptDisputeUnsettled = errors.New("script filter dispute not settled")

// banScriptFilterPeers bans and disconnects peers found to serve a wrong
// script filter.
func (b *blockManager) banScriptFilterPeers(peers []string) {
	for _, peer := range peers {
		log.Warnf("Banning peer %v, as it serves a wrong script filter", peer)
		if err := b.server.BanPeer(peer, banman.InvalidFilterHeader); err != nil {
			log.Errorf("Unable to ban peer %v: %v", peer, err)
		}
		if sp := b.server.PeerByAddr(peer); sp != nil {
			sp.Disconnect()
		}
	}
}

// settleScriptFiltersOfPeers finds the peers at fault among those that serve
// the given script filters for a block, with the proofs and leaves they give
// when asked.  It returns an error, with the peers found at fault so far,
// unless the peers it doesn't find at fault all serve one filter.
func (b *blockManager) settleScriptFiltersOfPeers(header *wire.BlockHeader,
	height uint32, filters map[string]servedScriptFilter) ([]string, error) {

	blockHash := header.BlockHash()
	proofs := func(peer string, index uint32) (*wire.MsgCFProof, error) {
		return b.scriptTrees.fetchScriptProof(peer, blockHash, index, b.quit)
	}
	ranges := func(peer string, bits uint16, prefix [32]byte) (*wire.MsgCFRange, error) {
		return b.scriptTrees.fetchScriptRange(peer, blockHash, bits, prefix, b.quit)
	}
	headers := func(hash *chainhash.Hash) (*wire.BlockHeader, uint32, bool) {
		prevHeader, prevHeight, err := b.server.BlockHeaders.FetchHeader(hash)
		return prevHeader, prevHeight, err == nil
	}
	return settleScriptFilters(
		blockHash, header, height, filters, proofs, ranges, headers,
		uint32(b.server.chainParams.MagneticAnonomalyForkHeight),
	)
}

// scriptFiltersOfPeers fetches the script filter of a block from every peer,
// and returns the filters of the peers for which backs returns true: those
// whose filter gives the filter hash or header they announced.  The others
// that served one are returned as bad.  A peer that serves none is in
// neither: it can't be told whether it would back what it announced.
func (b *blockManager) scriptFiltersOfPeers(header *wire.BlockHeader, height uint32,
	peers []string, backs func(peer string, f servedFilter) bool) (
	map[string]servedScriptFilter, []string) {

	served := b.fetchServedFilters(height, header.BlockHash(), wire.GCSFilterScripts)

	var badPeers []string
	filters := make(map[string]servedScriptFilter, len(peers))
	for _, peer := range peers {
		f, ok := served[peer]
		if !ok {
			log.Warnf("Peer %v did not respond to filter request", peer)
			continue
		}
		if f.filter == nil {
			log.Warnf("Peer %v served a filter that doesn't parse, "+
				"considering bad.", peer)
			badPeers = append(badPeers, peer)
			continue
		}
		data, err := f.filter.NBytes()
		if err != nil || !backs(peer, f) {
			log.Warnf("Peer %v serving filters not consistent with "+
				"filter hashes, considering bad.", peer)
			badPeers = append(badPeers, peer)
			continue
		}
		filters[peer] = servedScriptFilter{root: f.root, filter: data}
	}
	return filters, badPeers
}

// settleScriptClaims settles which of the claims peers made for a block's
// script filter, a filter hash or a filter header, is backed: it fetches the
// peers' filters, has backs check each against its claim, and tells the
// filters apart by the peers' proofs.  It returns the claim backed and the
// peers found at fault.  It returns an error, after banning the peers found
// at fault itself, unless every other peer made that claim: when a peer that
// made another didn't answer, we can't tell who's right, and no one is
// blamed for it.
func (b *blockManager) settleScriptClaims(header *wire.BlockHeader, height uint32,
	claims map[string]chainhash.Hash, backs func(peer string, f servedFilter) bool) (
	chainhash.Hash, []string, error) {

	peers := make([]string, 0, len(claims))
	for peer := range claims {
		peers = append(peers, peer)
	}
	filters, badPeers := b.scriptFiltersOfPeers(header, height, peers, backs)

	log.Warnf("Attempting to reconcile cfheader mismatch amongst %v peers "+
		"with their proofs", len(filters))

	settledBad, err := b.settleScriptFiltersOfPeers(header, height, filters)
	badPeers = append(badPeers, settledBad...)
	if err == nil {
		err = agreedClaim(claims, badPeers)
	}
	if err != nil {
		b.banScriptFilterPeers(badPeers)
		return chainhash.Hash{}, nil, fmt.Errorf("block %v at height %d: %w",
			header.BlockHash(), height, err)
	}

	for peer, claim := range claims {
		if !slices.Contains(badPeers, peer) {
			return claim, badPeers, nil
		}
	}
	return chainhash.Hash{}, badPeers, fmt.Errorf("%w: no peer could back "+
		"its script filter for block %v at height %d",
		errScriptDisputeUnsettled, header.BlockHash(), height)
}

// agreedClaim returns an error unless the peers not found at fault all made
// the same claim.
func agreedClaim(claims map[string]chainhash.Hash, badPeers []string) error {
	var (
		agreed chainhash.Hash
		seen   bool
	)
	for peer, claim := range claims {
		if slices.Contains(badPeers, peer) {
			continue
		}
		if seen && claim != agreed {
			return fmt.Errorf("%w: peer %v announced another filter "+
				"and didn't back it or show the other wrong",
				errScriptDisputeUnsettled, peer)
		}
		agreed, seen = claim, true
	}
	return nil
}

// detectBadScriptPeers finds which of the peers that announced different
// script filter hashes for a block serve a wrong filter.  A script filter
// lists the scripts of spent outputs, which the block doesn't hold, so the
// peers' proofs of what their entry trees hold settle it, not the block.  It
// returns an error unless the peers it doesn't find at fault all announced
// one filter hash.
func (b *blockManager) detectBadScriptPeers(header *wire.BlockHeader, height uint32,
	claims map[string]chainhash.Hash) ([]string, error) {

	_, badPeers, err := b.settleScriptClaims(header, height, claims,
		func(peer string, f servedFilter) bool {
			hash, err := servedFilterHash(wire.GCSFilterScripts, f.filter, f.root)
			return err == nil && hash == claims[peer]
		},
	)
	return badPeers, err
}

// scriptFilterHeaderOfPeers returns the script filter header of a block that
// the peers can back: the header of the filter left once the peers that
// announced different headers were told apart by their proofs.  claims holds
// the header each peer announced, all after the same previous header.  It
// returns an error unless the peers not found at fault all announced it.
func (b *blockManager) scriptFilterHeaderOfPeers(header *wire.BlockHeader,
	height uint32, prevHeader chainhash.Hash,
	claims map[string]chainhash.Hash) (chainhash.Hash, error) {

	want, _, err := b.settleScriptClaims(header, height, claims,
		func(peer string, f servedFilter) bool {
			filterHeader, err := servedFilterHeader(
				wire.GCSFilterScripts, f.filter, f.root, prevHeader,
			)
			return err == nil && filterHeader == claims[peer]
		},
	)
	return want, err
}

const (
	// scriptFilterProbeTries is how many times in a row a peer that is
	// current is asked whether it serves script filters before it is
	// taken not to, and scriptFilterProbePause is the pause between them.
	scriptFilterProbeTries = 2
	scriptFilterProbePause = 5 * time.Second

	// scriptFilterProbeRetry is how long we wait before asking a peer
	// that isn't current, or while our block headers aren't synced,
	// again.
	scriptFilterProbeRetry = time.Minute
)

// scriptFilterProbeWait is how long a peer has to answer a probe: a cfheaders
// message with one hash.
var scriptFilterProbeWait = replyWait{quiet: 15 * time.Second, most: time.Minute}

// probeAnswer is what a peer's answer to a probe showed.
type probeAnswer int

const (
	// probeServes is a genesis script filter header the same as ours.
	probeServes probeAnswer = iota

	// probeOther is a genesis script filter header other than ours: the
	// peer builds script filters another way.
	probeOther

	// probeSilent is no answer.
	probeSilent
)

// probeVerdict returns whether to keep probing a peer, and whether to
// disconnect it, after an answer to a probe.  silent counts the probes in a
// row a peer didn't answer while current, this one included.  bchd ignores
// getcfheaders while it isn't current, so a peer behind us is asked again
// later rather than dropped, and so is every peer while our own block headers
// aren't synced and we can't tell.
func probeVerdict(answer probeAnswer, current bool, silent int) (again, drop bool) {
	switch {
	case answer == probeServes:
		return false, false
	case answer == probeOther:
		return false, true
	case !current:
		return true, false
	default:
		return silent < scriptFilterProbeTries, silent >= scriptFilterProbeTries
	}
}

// probeScriptFilters checks that a new peer serves script filters, and
// disconnects it otherwise.  No service bit says which nodes keep them, and
// one that doesn't ignores requests for them, so we ask for the script
// filter header of the genesis block, which every node that keeps them has,
// and check it against ours.
func (s *ChainService) probeScriptFilters(sp *ServerPeer) {
	genesis := *s.chainParams.GenesisHash
	want, err := s.filterHeaders.FetchHeaderByHeight(0)
	if err != nil {
		log.Errorf("Unable to read the genesis script filter header: %v", err)
		return
	}

	silent := 0
	for {
		msg, err := s.askPeer(
			sp.Addr(), wire.NewMsgGetCFHeaders(wire.GCSFilterScripts, 0, &genesis),
			func(msg wire.Message) bool {
				headers, ok := msg.(*wire.MsgCFHeaders)
				return ok && headers.FilterType == wire.GCSFilterScripts &&
					headers.StopHash == genesis
			}, scriptFilterProbeWait, s.quit,
		)
		if errors.Is(err, ErrShuttingDown) || !sp.Connected() {
			return
		}

		answer, current := probeSilent, s.peerIsCurrent(sp)
		if msg != nil {
			answer = probeOther
			headers := msg.(*wire.MsgCFHeaders)
			if len(headers.FilterHashes) == 1 && headers.PrevFilterHeader == (chainhash.Hash{}) &&
				chainhash.DoubleHashH(append(headers.FilterHashes[0][:],
					headers.PrevFilterHeader[:]...)) == *want {

				answer = probeServes
			}
		}
		if answer == probeSilent && current {
			silent++
		} else {
			silent = 0
		}

		again, drop := probeVerdict(answer, current, silent)
		if drop {
			if answer == probeOther {
				log.Infof("Disconnecting peer %v, as it serves a genesis "+
					"script filter other than ours", sp)
			} else {
				log.Infof("Disconnecting peer %v, as it doesn't serve "+
					"script filters", sp)
			}
			sp.Disconnect()
			return
		}
		if !again {
			return
		}

		pause := scriptFilterProbeRetry
		if current {
			pause = scriptFilterProbePause
		}
		select {
		case <-time.After(pause):
		case <-sp.quit:
			return
		case <-s.quit:
			return
		}
	}
}

// peerIsCurrent returns whether a peer has announced our best block or a
// later one while our block headers are synced, so that it serves filters
// unless it doesn't keep them.
func (s *ChainService) peerIsCurrent(sp *ServerPeer) bool {
	if !s.blockManager.BlockHeadersSynced() {
		return false
	}
	_, height, err := s.BlockHeaders.ChainTip()
	return err == nil && sp.LastBlock() >= int32(height)
}

// ErrScriptFilterLacksOutput is returned when a block's script filter lacks
// the script or the token category of one of the block's outputs, or the ID
// of one of its transactions.
var errScriptFilterLacksOutput = errors.New("script filter lacks an output " +
	"or a transaction ID of its block")

// scriptFilterHoldsOutputs checks that a block's script filter holds the
// script and the token category of every output the block creates, and the
// ID of every transaction.  The scripts of the outputs it spends are not in
// the block, so they can't be checked this way.
func scriptFilterHoldsOutputs(filter *gcs.Filter, block *wire.MsgBlock) error {
	var keys [][32]byte
	for _, tx := range block.Transactions {
		keys = append(keys, builder.TxidKey(tx.TxHash()))
		for _, txOut := range tx.TxOut {
			if script := txOut.PkScript; len(script) > 0 && script[0] != 0x6a {
				keys = append(keys, builder.ScriptKey(script))
			}
			if !txOut.TokenData.IsEmpty() {
				keys = append(keys, builder.CategoryKey(txOut.TokenData.CategoryID))
			}
		}
	}
	if len(keys) == 0 {
		return nil
	}

	// Matching the keys one at a time would read the filter once for each,
	// so we read its values once and look each key's value up in them, as
	// gcs.Filter does to match one: a key's value is its SipHash-2-4 under
	// the first half of the block hash, scaled to N*M.
	values, err := gcsFilterValues(filter)
	if err != nil {
		return fmt.Errorf("%w: %v", errScriptFilterLacksOutput, err)
	}
	blockHash := block.BlockHash()
	key := builder.DeriveKey(&blockHash)
	modulus := uint64(filter.N()) * builder.DefaultM
	for i := range keys {
		value, _ := bits.Mul64(siphash.Sum64(keys[i][:], &key), modulus)
		at := sort.Search(len(values), func(j int) bool { return values[j] >= value })
		if at == len(values) || values[at] != value {
			return fmt.Errorf("%w %v: key %x", errScriptFilterLacksOutput,
				blockHash, keys[i])
		}
	}
	return nil
}

// errFilterTooManyValues is returned for a filter whose N is more than its
// bytes can hold.
var errFilterTooManyValues = errors.New("filter claims more values than its " +
	"bytes hold")

// checkFilterN returns errFilterTooManyValues when a filter's N is more than
// its data can hold: every value takes at least P+1 bits, the one that ends
// its quotient and P of remainder.  N comes from whoever served the filter,
// and a peer controls a header chain without checkpoints, as script
// filters have, so nothing is sized by N before this check.
func checkFilterN(n uint32, p uint8, data []byte) error {
	if uint64(n) > uint64(len(data))*8/(uint64(p)+1) {
		return fmt.Errorf("%w: %d values in %d bytes", errFilterTooManyValues,
			n, len(data))
	}
	return nil
}

// gcsFilterValues returns the values a filter holds, in order: the sums of
// its Golomb-Rice coded differences.
func gcsFilterValues(filter *gcs.Filter) ([]uint64, error) {
	data, err := filter.Bytes()
	if err != nil {
		return nil, err
	}
	if err := checkFilterN(filter.N(), filter.P(), data); err != nil {
		return nil, err
	}
	stream := bstream.NewBStreamReader(data)
	values := make([]uint64, 0, filter.N())
	var last uint64
	for range filter.N() {
		var quotient uint64
		for {
			bit, err := stream.ReadBit()
			if err != nil {
				return nil, err
			}
			if !bit {
				break
			}
			quotient++
		}
		remainder, err := stream.ReadBits(int(filter.P()))
		if err != nil {
			return nil, err
		}
		last += quotient<<filter.P() + remainder
		values = append(values, last)
	}
	return values, nil
}

// verifyScriptBlockFilter checks a downloaded block against the script filter
// synced for it.  On a mismatch a repair of the filter headers is requested,
// which the peers' proofs settle, and ErrBlockFilterMismatch is returned.
func (s *ChainService) verifyScriptBlockFilter(block *bchutil.Block,
	height uint32) error {

	// Without the filter there is nothing to check the block against, and
	// fetching it would make GetBlock wait on the network.  It is held
	// when the block was fetched because it matched.
	filter, err := s.heldFilter(*block.Hash(), wire.GCSFilterScripts)
	if err != nil || filter == nil {
		return nil
	}
	err = scriptFilterHoldsOutputs(filter, block.MsgBlock())
	if err == nil {
		return nil
	}
	if !errors.Is(err, errScriptFilterLacksOutput) {
		return err
	}

	// The filter read above belongs to another block if a reorg replaced
	// this one in the meantime.
	header, headerErr := s.BlockHeaders.FetchHeaderByHeight(height)
	if headerErr != nil || header.BlockHash() != *block.Hash() {
		return nil
	}

	log.Warnf("The script filter synced for block %v at height %d doesn't "+
		"hold its outputs and transaction IDs: %v", block.Hash(), height, err)

	s.blockManager.requestFilterHeaderRepair()

	return fmt.Errorf("%w: block %v at height %d", ErrBlockFilterMismatch,
		block.Hash(), height)
}
