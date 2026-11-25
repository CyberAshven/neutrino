package neutrino

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"slices"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs"
	"github.com/gcash/bchutil/gcs/builder"
)

// A script filter (filter type 1) lists the scripts of the outputs a block
// spends, which sit in older blocks, so a filter can't be rebuilt from its
// block to tell which of two peers serves a wrong one, as the regular filter
// is.  Each script filter is served with the root of a Merkle tree over the
// block's sorted entries, its leaves, and a peer proves any leaf of its tree
// with a cfproof message.  Two peers that serve different roots are told
// apart with those proofs alone:
//
//   - The first leaf at which their trees differ is found by a binary search
//     over leaf indexes.  The branch of leaf i holds the hashes of the full
//     blocks of leaves to its left, which are the same in both trees however
//     many leaves each has, so two peers agree on leaves 0 to i exactly when
//     they give the same leaf i and the same hashes to its left.
//   - Of the two leaves there, the one that sorts first can't be anywhere in
//     the other peer's tree if that tree is sorted.  Its proof shows whether
//     it is a true entry of the block: the transaction it names under the
//     block's Merkle root, and for a spent output, the output's transaction
//     under the Merkle root of its own block.  If it is, the other peer left
//     it out or misplaced it.  If it isn't, the peer that holds it made it
//     up.
//
// Either way one of the two serves a wrong filter, and a few dozen small
// messages decide which, whatever the size of the block.  The requests name
// leaf indexes, so they say nothing of what we watch.
//
// Only a proof counts against a peer: a leaf the other peer proves true that
// the peer's tree can't hold, a leaf of its own tree that isn't true, or a
// reply that doesn't fit the root the peer itself serves, which an honest
// node's reply always does.  A peer that doesn't answer may only be catching
// up, as bchd ignores these requests while it isn't current: it can't be told
// apart, and is not blamed.
//
// A peer can also serve the true root in front of a filter that doesn't hold
// the tree's keys.  Peers that agree on the root and not on the filter are
// told apart by the leaves themselves: every leaf is fetched from one of
// them with cfrange messages, in runs by key prefix that are each checked
// against the root, and the filter built from them is the one a peer must
// serve.  That costs 41 bytes a leaf, about half the size of the block, and
// only when a peer lies this way.

// scriptProofSource asks a peer for the cfproof of one leaf of the entry tree
// of the block in dispute.  It returns errNoAnswer when the peer doesn't
// answer, and ErrShuttingDown when we are shutting down.
type scriptProofSource func(peer string, index uint32) (*wire.MsgCFProof, error)

// scriptHeaderSource returns the header and height of a block of our best
// chain, or false when the block isn't in it.
type scriptHeaderSource func(hash *chainhash.Hash) (*wire.BlockHeader, uint32, bool)

// errScriptProof is returned for a cfproof that doesn't fit the tree of the
// peer that sent it.
var errScriptProof = errors.New("cfproof does not fit the peer's entry tree")

// scriptLeafProof is a leaf a peer proved to be in its tree.
type scriptLeafProof struct {
	leaf builder.ScriptLeaf

	// lefts are the hashes in the leaf's branch that stand left of its
	// path, from the leaves up: the roots of the full blocks of leaves
	// before it.
	lefts []chainhash.Hash

	msg *wire.MsgCFProof
}

// scriptTree is what we know of one peer's entry tree for the block.
type scriptTree struct {
	peer   string
	block  chainhash.Hash
	root   chainhash.Hash
	fetch  scriptProofSource
	proofs map[uint32]*scriptLeafProof

	// count is the number of leaves the peer's first proof gave, which
	// its later proofs must give too.  A tree with the zero root has no
	// leaves.
	count      uint32
	countKnown bool
}

// newScriptTree returns the tree of a peer that serves root for the block.
func newScriptTree(peer string, block, root chainhash.Hash, fetch scriptProofSource) *scriptTree {
	t := &scriptTree{
		peer:   peer,
		block:  block,
		root:   root,
		fetch:  fetch,
		proofs: make(map[uint32]*scriptLeafProof),
	}
	if root == (chainhash.Hash{}) {
		t.countKnown = true
	}
	return t
}

// leafCount returns the number of leaves in the peer's tree.
func (t *scriptTree) leafCount() (uint32, error) {
	if !t.countKnown {
		if _, err := t.leaf(0); err != nil {
			return 0, err
		}
	}
	return t.count, nil
}

// leaf returns the proof of the leaf at index in the peer's tree, checked
// against the root the peer serves.  It returns errScriptProof for a reply
// that doesn't fit the tree, and the source's error when there is no reply.
func (t *scriptTree) leaf(index uint32) (*scriptLeafProof, error) {
	if proof, ok := t.proofs[index]; ok {
		return proof, nil
	}
	msg, err := t.fetch(t.peer, index)
	if err != nil {
		return nil, err
	}
	if msg.FilterType != wire.GCSFilterScripts || msg.BlockHash != t.block ||
		msg.LeafIndex != index || msg.LeafIndex >= msg.LeafCount ||
		(t.countKnown && msg.LeafCount != t.count) {

		return nil, fmt.Errorf("%w: leaf %d of %d", errScriptProof,
			msg.LeafIndex, msg.LeafCount)
	}
	leaf, err := builder.ParseScriptLeaf(msg.Leaf[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errScriptProof, err)
	}
	root, err := builder.ScriptRangeRoot(
		msg.LeafCount, index, []builder.ScriptLeaf{leaf}, msg.LeafBranch,
	)
	if err != nil || root != t.root {
		return nil, fmt.Errorf("%w: leaf %d does not rebuild the root",
			errScriptProof, index)
	}

	// The branch lists one hash for each level at which the path has a
	// partner: a left one where the path's index is odd, a right one
	// where it is even and not the last of its level.
	proof := &scriptLeafProof{leaf: leaf, msg: msg}
	branch := msg.LeafBranch
	for at, width := uint64(index), uint64(msg.LeafCount); width > 1; at, width = at/2, (width+1)/2 {
		switch {
		case at%2 == 1:
			proof.lefts = append(proof.lefts, branch[0])
			branch = branch[1:]
		case at+1 < width:
			branch = branch[1:]
		}
	}

	t.count, t.countKnown = msg.LeafCount, true
	t.proofs[index] = proof
	return proof, nil
}

// compareScriptLeaves orders leaves as the entry tree does: by key, then
// transaction index, then input or output index, then kind.
func compareScriptLeaves(a, b *builder.ScriptLeaf) int {
	if c := bytes.Compare(a.Key[:], b.Key[:]); c != 0 {
		return c
	}
	for _, pair := range [][2]uint32{
		{a.TxIndex, b.TxIndex}, {a.Index, b.Index}, {uint32(a.Kind), uint32(b.Kind)},
	} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	return 0
}

// checkTxMerkleBranch checks that the transaction with the given ID is the
// one at index under a block's Merkle root.
func checkTxMerkleBranch(txid chainhash.Hash, index uint32, branch []chainhash.Hash,
	merkleRoot *chainhash.Hash) bool {

	if len(branch) > wire.MaxCFTreeDepth || uint64(index)>>uint(len(branch)) != 0 {
		return false
	}
	hash := txid
	for at, i := index, 0; i < len(branch); at, i = at/2, i+1 {
		// The last node of a level without a partner is hashed with
		// itself, as a left child.  A right child equal to its partner
		// would be that copy, at an index the block doesn't have.
		if at%2 == 1 && branch[i] == hash {
			return false
		}
		if at%2 == 1 {
			hash = *blockchain.HashMerkleBranches(&branch[i], &hash)
		} else {
			hash = *blockchain.HashMerkleBranches(&hash, &branch[i])
		}
	}
	return hash == *merkleRoot
}

// scriptLeafOf returns whether an output gives a leaf's key: its script for a
// leaf of a script, its token category for a leaf of a category.
func scriptLeafOf(txOut *wire.TxOut, key *[32]byte, category bool) bool {
	if category {
		return !txOut.TokenData.IsEmpty() &&
			builder.CategoryKey(txOut.TokenData.CategoryID) == *key
	}
	script := txOut.PkScript
	return len(script) > 0 && script[0] != 0x6a && builder.ScriptKey(script) == *key
}

// isTrueScriptLeaf checks what a proved leaf points to: whether the block
// with the given header and height really has the entry.  The transaction the
// leaf names must be under the block's Merkle root, and its output, or for a
// leaf of a spent output the output its input spends, must give the leaf's
// key; for the leaf of a transaction's ID, at index 0, its ID must.  A spent
// output's transaction must be under the Merkle root of a block of our chain
// no higher than the block.  smallTxUntil is the last height at which a block
// may hold a transaction of 64 bytes.
func isTrueScriptLeaf(proof *scriptLeafProof, header *wire.BlockHeader, height uint32,
	headers scriptHeaderSource, smallTxUntil uint32) bool {

	leaf, msg := &proof.leaf, proof.msg
	tx := msg.Tx

	// At or below smallTxUntil a 64-byte transaction is a valid one and is
	// judged by its Merkle branch like any other.  Above that height no
	// block can hold one, so 64 bytes there can only be an inner node of
	// the Merkle tree.  A spent output's transaction is judged the same way
	// at its own block's height, which is known once that header is read.
	if tx == nil || (height > smallTxUntil && tx.SerializeSize() == 64) ||
		!checkTxMerkleBranch(tx.TxHash(), leaf.TxIndex, msg.TxBranch, &header.MerkleRoot) {

		return false
	}
	if leaf.Kind == builder.ScriptLeafTransaction {
		return leaf.Index == 0 && builder.TxidKey(tx.TxHash()) == leaf.Key
	}
	category := leaf.Kind == builder.ScriptLeafOutputCategory ||
		leaf.Kind == builder.ScriptLeafSpentCategory

	if !msg.Leaf.Spent() {
		return leaf.Index < uint32(len(tx.TxOut)) &&
			scriptLeafOf(tx.TxOut[leaf.Index], &leaf.Key, category)
	}

	// The coinbase spends no output.
	if leaf.TxIndex == 0 || leaf.Index >= uint32(len(tx.TxIn)) || msg.PrevTx == nil {
		return false
	}
	prevOut := &tx.TxIn[leaf.Index].PreviousOutPoint
	prevTx := msg.PrevTx
	if prevTx.TxHash() != prevOut.Hash ||
		prevOut.Index >= uint32(len(prevTx.TxOut)) {

		return false
	}
	prevHeader, prevHeight, ok := headers(&msg.PrevBlockHash)
	if !ok || prevHeight > height || !checkTxMerkleBranch(
		prevOut.Hash, msg.PrevTxIndex, msg.PrevTxBranch, &prevHeader.MerkleRoot,
	) {
		return false
	}
	if prevHeight > smallTxUntil && prevTx.SerializeSize() == 64 {
		return false
	}
	return scriptLeafOf(prevTx.TxOut[prevOut.Index], &leaf.Key, category)
}

// scriptVerdict is how a comparison of two peers' entry trees ended.
type scriptVerdict struct {
	// bad is the peer found at fault, or empty when the two couldn't be
	// told apart.
	bad string

	// wrongTree is whether bad's tree is wrong, so that every peer that
	// serves the same root is at fault too.  It is false when bad only
	// sent a reply that doesn't fit its own tree.
	wrongTree bool

	// silent is a peer that didn't answer, so that the two couldn't be
	// told apart.
	silent string
}

// verdictOn returns how a comparison ends when a peer's tree gave err:
// shutting down ends it with the error, a peer that didn't answer can't be
// told apart, and a reply that doesn't fit the peer's own tree is its fault.
func verdictOn(t *scriptTree, err error) (scriptVerdict, error) {
	switch {
	case errors.Is(err, ErrShuttingDown):
		return scriptVerdict{}, err
	case errors.Is(err, errNoAnswer):
		return scriptVerdict{silent: t.peer}, nil
	default:
		return scriptVerdict{bad: t.peer}, nil
	}
}

// settleScriptTrees finds which of two peers that serve different roots for
// a block is at fault.  smallTxUntil is the last height at which a block may
// hold a transaction of 64 bytes.  It returns an error only when we are
// shutting down.
func settleScriptTrees(a, b *scriptTree, header *wire.BlockHeader, height uint32,
	headers scriptHeaderSource, smallTxUntil uint32) (scriptVerdict, error) {

	countA, err := a.leafCount()
	if err != nil {
		return verdictOn(a, err)
	}
	countB, err := b.leafCount()
	if err != nil {
		return verdictOn(b, err)
	}

	// Find the first index at which the trees differ: the lowest one below
	// both counts where the leaves, or the hashes left of them, differ, or
	// else the end of the shorter tree.
	lo, hi := uint32(0), min(countA, countB)
	for lo < hi {
		mid := lo + (hi-lo)/2
		proofA, err := a.leaf(mid)
		if err != nil {
			return verdictOn(a, err)
		}
		proofB, err := b.leaf(mid)
		if err != nil {
			return verdictOn(b, err)
		}
		same := proofA.leaf == proofB.leaf && len(proofA.lefts) == len(proofB.lefts)
		for i := 0; same && i < len(proofA.lefts); i++ {
			same = proofA.lefts[i] == proofB.lefts[i]
		}
		if same {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	first := lo

	// Take the leaf there that sorts first, or the only one when one tree
	// ends there.
	holder, other := a, b
	switch {
	case first == countA && first == countB:
		// The same leaves under different roots, which proofs that
		// rebuild their roots can't give but for a hash collision: we
		// can't tell which is wrong.
		return scriptVerdict{}, nil
	case first == countA:
		holder, other = b, a
	case first < countB:
		proofA, err := a.leaf(first)
		if err != nil {
			return verdictOn(a, err)
		}
		proofB, err := b.leaf(first)
		if err != nil {
			return verdictOn(b, err)
		}
		switch c := compareScriptLeaves(&proofA.leaf, &proofB.leaf); {
		case c == 0:
			return scriptVerdict{}, nil
		case c > 0:
			holder, other = b, a
		}
	}
	proof, err := holder.leaf(first)
	if err != nil {
		return verdictOn(holder, err)
	}

	// The leaf must come after the one before it, or the holder's tree
	// repeats a leaf or is out of order.
	if first > 0 {
		before, err := holder.leaf(first - 1)
		if err != nil {
			return verdictOn(holder, err)
		}
		if compareScriptLeaves(&before.leaf, &proof.leaf) >= 0 {
			return scriptVerdict{bad: holder.peer, wrongTree: true}, nil
		}
	}

	// A true entry that sorts before the other peer's leaf there, with
	// the same leaves before both, is not in the other peer's tree where
	// a sorted tree would have it.
	if isTrueScriptLeaf(proof, header, height, headers, smallTxUntil) {
		return scriptVerdict{bad: other.peer, wrongTree: true}, nil
	}
	return scriptVerdict{bad: holder.peer, wrongTree: true}, nil
}

// settleScriptFilterDispute returns the peers at fault among those that serve
// the given entry tree roots for one block, when the roots are not all the
// same.  Peers are compared two at a time until those left serve one root.
// One peer that serves the true filter and proves its leaves is enough for
// every other root to be found wrong.  smallTxUntil is the last height at
// which a block may hold a transaction of 64 bytes.  It also returns the
// peers that couldn't be told apart from another, as they didn't answer, and
// an error only when we are shutting down.
func settleScriptFilterDispute(block chainhash.Hash, header *wire.BlockHeader,
	height uint32, roots map[string]chainhash.Hash, fetch scriptProofSource,
	headers scriptHeaderSource, smallTxUntil uint32) (bad, unsure []string, err error) {

	trees := make(map[string]*scriptTree, len(roots))
	for peer, root := range roots {
		trees[peer] = newScriptTree(peer, block, root, fetch)
	}

	for {
		// Pick two peers that serve different roots.
		var a, b *scriptTree
		for _, t := range trees {
			switch {
			case a == nil:
				a = t
			case t.root != a.root:
				b = t
			}
			if b != nil {
				break
			}
		}
		if b == nil {
			return bad, unsure, nil
		}

		verdict, err := settleScriptTrees(a, b, header, height, headers, smallTxUntil)
		if err != nil {
			return bad, unsure, err
		}
		switch {
		case verdict.silent != "":
			// It is left out of the dispute, without blame.
			log.Warnf("Peer %v didn't answer for its script filter of "+
				"block %v", verdict.silent, block)
			unsure = append(unsure, verdict.silent)
			delete(trees, verdict.silent)
			continue

		case verdict.bad == "":
			// Neither can be shown wrong by the other.  Both are
			// left out, without blame, so that the dispute ends.
			log.Warnf("Could not tell which of %v and %v serves a "+
				"wrong script filter for block %v", a.peer, b.peer, block)
			unsure = append(unsure, a.peer, b.peer)
			delete(trees, a.peer)
			delete(trees, b.peer)
			continue
		}
		badRoot := trees[verdict.bad].root
		for peer, t := range trees {
			if peer == verdict.bad || (verdict.wrongTree && t.root == badRoot) {
				bad = append(bad, peer)
				delete(trees, peer)
			}
		}
	}
}

// scriptRangeSource asks a peer for the leaves of the entry tree of the block
// in dispute whose keys start with the first bits of prefix.  It returns
// errNoAnswer when the peer doesn't answer, and ErrShuttingDown when we are
// shutting down.
type scriptRangeSource func(peer string, bits uint16, prefix [32]byte) (*wire.MsgCFRange, error)

// scriptLeavesPerRange is about how many leaves we ask a peer for at once: a
// few megabytes of them.
var scriptLeavesPerRange uint32 = 100000

// maxScriptLeaves returns the most leaves the entry tree of a block we would
// take can have.  An output takes at least 10 bytes of its block and gives
// one leaf, or two with tokens, which take more than 10 bytes more, an input
// takes more than 40 bytes and gives two at most, and a transaction takes at
// least 10 bytes besides its inputs and outputs and gives the one leaf of its
// ID.  It keeps a peer from sending leaves without end for a tree no block
// gives.
var maxScriptLeaves = func() uint64 {
	return uint64(wire.MaxBlockPayload()) / 10
}

// maxRangeLeaves returns how many leaves a range surely fits one cfrange with.
// bchd doesn't answer for a range larger than one message, which holds twice
// a block's largest size, and the client is to ask again with a longer
// prefix.  Half of that leaves room for a node whose largest block is
// smaller.
var maxRangeLeaves = func() uint64 {
	return uint64(wire.MaxBlockPayload()) / wire.CFLeafSize
}

// parseScriptRange parses the leaves of a cfrange message.
func parseScriptRange(msg *wire.MsgCFRange) (run []builder.ScriptLeaf,
	before, after *builder.ScriptLeaf, err error) {

	run = make([]builder.ScriptLeaf, len(msg.Leaves))
	for i := range msg.Leaves {
		if run[i], err = builder.ParseScriptLeaf(msg.Leaves[i][:]); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, neighbour := range []struct {
		from *wire.CFLeaf
		to   **builder.ScriptLeaf
	}{{msg.Before, &before}, {msg.After, &after}} {
		if neighbour.from == nil {
			continue
		}
		leaf, err := builder.ParseScriptLeaf(neighbour.from[:])
		if err != nil {
			return nil, nil, nil, err
		}
		*neighbour.to = &leaf
	}
	return run, before, after, nil
}

// keySpace is the number of keys: 2^256.
var keySpace = new(big.Int).Lsh(big.NewInt(1), 256)

// keyBlock is the block of keys that start with the first bits of a prefix.
type keyBlock struct {
	prefix [32]byte
	bits   uint16
}

// keyBlockAt returns the block at the given start of the given length.
func keyBlockAt(start *big.Int, bits uint16) keyBlock {
	var b keyBlock
	start.FillBytes(b.prefix[:])
	b.bits = bits
	return b
}

// start returns the block's first key.
func (b keyBlock) start() *big.Int {
	return new(big.Int).SetBytes(b.prefix[:])
}

// end returns the key after the block's last one.
func (b keyBlock) end() *big.Int {
	return new(big.Int).Add(b.start(), new(big.Int).Lsh(big.NewInt(1), uint(256-b.bits)))
}

// holds returns whether a key starts with the block's prefix.
func (b keyBlock) holds(key [32]byte) bool {
	return prefixBits(b.prefix, key) >= b.bits
}

// prefixBits returns how many first bits two keys share.
func prefixBits(a, b [32]byte) uint16 {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return uint16(i*8 + bits.LeadingZeros8(x))
		}
	}
	return 256
}

// alignedBits returns the fewest bits of a block that starts at a key: a
// block starts at a multiple of its size.
func alignedBits(start *big.Int) uint16 {
	if start.Sign() == 0 {
		return 0
	}
	return uint16(256 - start.TrailingZeroBits())
}

// fetchScriptLeaves fetches every leaf of the entry tree with the given root
// from a peer that serves it, in runs by key prefix.  Each run is checked
// against the root, which shows that it leaves out no leaf with its prefix
// and that its leaves are in order, so the runs together are the whole tree.
//
// The runs walk the keys in order.  bchd doesn't answer for a run too large
// for one message, and many leaves can share a prefix, or a key, in a block
// made that way.  So while more leaves are left than a run is to hold, the
// leaf that many after the next one is proved first: a run whose prefix that
// leaf's key has would hold too many, and is split in two, the first half
// asked for first, until one holds fewer.  The leaves of one key are asked
// for whatever their number.  A peer that doesn't answer for a run that fits
// returns errNoAnswer, and so does one whose leaves of one key are too many
// for a message: it can't be told what the tree holds, and is not blamed.
func fetchScriptLeaves(peer string, block, root chainhash.Hash,
	ranges scriptRangeSource, proofs scriptProofSource) ([]builder.ScriptLeaf, error) {

	ask := func(b keyBlock) (*wire.MsgCFRange, []builder.ScriptLeaf, error) {
		msg, err := ranges(peer, b.bits, b.prefix)
		if err != nil {
			return nil, nil, err
		}
		if msg.FilterType != wire.GCSFilterScripts || msg.BlockHash != block {
			return nil, nil, fmt.Errorf("%w: cfrange for another block", errScriptProof)
		}
		run, before, after, err := parseScriptRange(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errScriptProof, err)
		}
		err = builder.CheckScriptRange(root, msg.LeafCount, msg.FirstIndex, run,
			before, after, msg.Hashes, &b.prefix, b.bits)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errScriptProof, err)
		}
		return msg, run, nil
	}

	// The range of one whole key is small, and tells how many leaves the
	// tree has.
	first, _, err := ask(keyBlock{bits: wire.MaxCFRangePrefixBits})
	if err != nil {
		return nil, err
	}
	count := first.LeafCount
	if uint64(count) > maxScriptLeaves() {
		return nil, fmt.Errorf("%w: %d leaves are more than a block gives",
			errScriptProof, count)
	}

	// Split the keys by enough of their first bits that a run has about
	// scriptLeavesPerRange leaves, and take a run to hold too many with
	// twice that, or with more than surely fit a message.
	var perRun uint16
	for perRun < 16 && count>>perRun > scriptLeavesPerRange {
		perRun++
	}
	most := min(2*uint64(scriptLeavesPerRange), maxRangeLeaves())

	// heavy returns whether a run that starts at the next leaf holds most
	// leaves or more: whether the leaf most-1 after the next one has the
	// run's prefix.  That leaf's proof comes from the same tree as the
	// runs, and is kept until a run is fetched.
	tree := newScriptTree(peer, block, root, proofs)
	heavy := func(b keyBlock, next uint64) (bool, error) {
		if uint64(count)-next <= most {
			return false, nil
		}
		proof, err := tree.leaf(uint32(next + most - 1))
		if err != nil {
			return false, err
		}
		if tree.count != count {
			return false, fmt.Errorf("%w: proofs of a tree of %d leaves, "+
				"ranges of %d", errScriptProof, tree.count, count)
		}
		key := new(big.Int).SetBytes(proof.leaf.Key[:])
		if key.Cmp(b.start()) < 0 {
			return false, fmt.Errorf("%w: leaf %d sorts before the "+
				"leaves fetched", errScriptProof, next+most-1)
		}
		return b.holds(proof.leaf.Key), nil
	}

	// Not sized by the peer's count: memory grows only with the leaves
	// that were sent and checked against the root.  Every key below the
	// cursor is done, and a run starts at a multiple of its size.
	var leaves []builder.ScriptLeaf
	cursor := new(big.Int)
	b := keyBlockAt(cursor, perRun)
	for {
		split, err := heavy(b, uint64(len(leaves)))
		if err != nil {
			return nil, err
		}
		if split && b.bits < wire.MaxCFRangePrefixBits {
			b.bits++
			continue
		}
		msg, run, err := ask(b)
		if err != nil {
			return nil, err
		}
		if msg.LeafCount != count || msg.FirstIndex != uint32(len(leaves)) {
			return nil, fmt.Errorf("%w: run %x/%d starts at leaf %d of %d, "+
				"after %d of %d", errScriptProof, b.prefix[:4], b.bits,
				msg.FirstIndex, msg.LeafCount, len(leaves), count)
		}
		leaves = append(leaves, run...)
		if len(run) > 0 {
			tree.proofs = make(map[uint32]*scriptLeafProof)
		}

		cursor = b.end()
		if cursor.Cmp(keySpace) >= 0 {
			break
		}
		b = keyBlockAt(cursor, max(perRun, alignedBits(cursor)))
	}
	if uint32(len(leaves)) != count {
		return nil, fmt.Errorf("%w: %d leaves of %d", errScriptProof, len(leaves), count)
	}
	return leaves, nil
}

// scriptFilterOfLeaves builds the script filter of a block from the leaves of
// its entry tree.
func scriptFilterOfLeaves(block *chainhash.Hash, leaves []builder.ScriptLeaf) (*gcs.Filter, error) {
	b := builder.WithKeyHash(block)
	if _, err := b.Key(); err != nil {
		return nil, err
	}
	for i := range leaves {
		b.AddEntry(leaves[i].Key[:])
	}
	return b.Build()
}

// servedScriptFilter is a script filter as a peer serves it: the root of the
// block's entry tree, and the serialized filter after it.
type servedScriptFilter struct {
	root   chainhash.Hash
	filter []byte
}

// settleScriptFilters returns the peers at fault among those that serve the
// given script filters for one block, when the filters are not all the same.
// Peers that serve different roots are told apart first, by their proofs of
// single leaves.  If those left still serve different filters under one
// root, the filter is built from that tree's leaves, and the peers that serve
// another are at fault.  smallTxUntil is the last height at which a block
// may hold a transaction of 64 bytes.
//
// It returns an error, with the peers found at fault so far, unless the peers
// it doesn't find at fault all serve one filter: when a peer that serves
// another didn't answer, when no peer gives the leaves, when the filter can't
// be built from them, and when we are shutting down.
func settleScriptFilters(block chainhash.Hash, header *wire.BlockHeader, height uint32,
	served map[string]servedScriptFilter, proofs scriptProofSource,
	ranges scriptRangeSource, headers scriptHeaderSource, smallTxUntil uint32) ([]string, error) {

	roots := make(map[string]chainhash.Hash, len(served))
	for peer, f := range served {
		roots[peer] = f.root
	}
	badPeers, unsure, err := settleScriptFilterDispute(block, header, height, roots,
		proofs, headers, smallTxUntil)
	if err != nil {
		return badPeers, err
	}
	left := make(map[string]servedScriptFilter, len(served))
	for peer, f := range served {
		if !slices.Contains(badPeers, peer) && !slices.Contains(unsure, peer) {
			left[peer] = f
		}
	}
	var root chainhash.Hash
	for _, f := range left {
		root = f.root
		break
	}

	// The peers left serve one root, and so may peers that didn't answer
	// for it.  If they serve different filters under it, any of them can
	// give the leaves, as those are checked against the root: those left
	// first.  One that sends a range that doesn't fit the root is at fault,
	// and one that doesn't answer is not.
	var underRoot []string
	for peer := range left {
		underRoot = append(underRoot, peer)
	}
	for _, peer := range unsure {
		if len(left) > 0 && served[peer].root == root {
			underRoot = append(underRoot, peer)
		}
	}
	if !oneScriptFilter(served, underRoot) {
		var want []byte
		for _, from := range underRoot {
			leaves, err := fetchScriptLeaves(from, block, root, ranges,
				func(_ string, index uint32) (*wire.MsgCFProof, error) {
					return proofs(from, index)
				})
			switch {
			case errors.Is(err, ErrShuttingDown):
				return badPeers, err

			case errors.Is(err, errNoAnswer):
				log.Warnf("Peer %v didn't give the leaves of block %v",
					from, block)
				continue

			case err != nil:
				log.Warnf("Peer %v gave leaves of block %v that don't "+
					"fit its root: %v", from, block, err)
				badPeers = append(badPeers, from)
				continue
			}

			filter, err := scriptFilterOfLeaves(&block, leaves)
			if err != nil {
				return badPeers, fmt.Errorf("unable to build the script "+
					"filter of block %v from its leaves: %w", block, err)
			}
			if want, err = filter.NBytes(); err != nil {
				return badPeers, fmt.Errorf("unable to serialize the "+
					"script filter of block %v: %w", block, err)
			}
			break
		}
		if want == nil {
			return badPeers, fmt.Errorf("%w: no peer that serves root %v "+
				"of block %v gave its leaves", errScriptDisputeUnsettled,
				root, block)
		}

		// Every peer that serves the root serves the filter of its
		// leaves, or is at fault, whether it answered or not.
		for _, peer := range underRoot {
			if slices.Contains(badPeers, peer) {
				delete(left, peer)
				continue
			}
			if !bytes.Equal(served[peer].filter, want) {
				badPeers = append(badPeers, peer)
				delete(left, peer)
				continue
			}
			left[peer] = served[peer]
		}
		unsure = slices.DeleteFunc(unsure, func(peer string) bool {
			_, ok := left[peer]
			return ok || slices.Contains(badPeers, peer)
		})
	}

	// A peer that didn't answer and serves another filter than the peers
	// left may be the one that's right.
	for _, peer := range unsure {
		if _, ok := left[peer]; ok {
			continue
		}
		if len(left) == 0 || !oneScriptFilter(served, []string{peer, anyPeer(left)}) {
			return badPeers, fmt.Errorf("%w: peer %v serves another filter "+
				"for block %v and didn't answer", errScriptDisputeUnsettled,
				peer, block)
		}
	}
	return badPeers, nil
}

// anyPeer returns one of the peers of a map.
func anyPeer(peers map[string]servedScriptFilter) string {
	for peer := range peers {
		return peer
	}
	return ""
}

// oneScriptFilter returns whether the given peers serve one filter, under one
// root.
func oneScriptFilter(served map[string]servedScriptFilter, peers []string) bool {
	for _, peer := range peers {
		f, one := served[peer], served[peers[0]]
		if f.root != one.root || !bytes.Equal(f.filter, one.filter) {
			return false
		}
	}
	return true
}
