package neutrino

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/rpcclient"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/bchwallet/waddrmgr"
)

// scriptRescanChain is a mock chain source that syncs script filters, whose
// blocks hold the transactions the test gives them.
type scriptRescanChain struct {
	*mockChainSource

	// scripts are the scripts of the outputs made so far, with their
	// token prefixes, as a node's spend journal gives them.
	scripts map[wire.OutPoint][]byte

	// stop ends the goroutines that take the mock's reports of the filters
	// and blocks asked for.
	stop chan struct{}
}

// newScriptRescanChain returns a chain of the genesis block that syncs script
// filters.
func newScriptRescanChain(t *testing.T) *scriptRescanChain {
	t.Helper()
	c := &scriptRescanChain{
		mockChainSource: newMockChainSource(1),
		scripts:         make(map[wire.OutPoint][]byte),
		stop:            make(chan struct{}),
	}
	c.filterType = wire.GCSFilterScripts
	for _, queried := range []chan chainhash.Hash{c.filtersQueried, c.blocksQueried} {
		go func() {
			for {
				select {
				case <-queried:
				case <-c.stop:
					return
				}
			}
		}()
	}
	t.Cleanup(func() { close(c.stop) })
	return c
}

// addBlock adds a block with a coinbase and the given transactions, and its
// script filter.
func (c *scriptRescanChain) addBlock(t *testing.T, txs ...*wire.MsgTx) waddrmgr.BlockStamp {
	t.Helper()
	header := c.nextHeader()
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{},
		wire.MaxPrevOutIndex), []byte{byte(header.Timestamp.Unix()), 0x51}))
	coinbase.AddTxOut(wire.NewTxOut(5000, disputeScript(0x01), wire.TokenData{}))
	msgBlock := wire.NewMsgBlock(header)
	msgBlock.Transactions = append([]*wire.MsgTx{coinbase}, txs...)
	block := bchutil.NewBlock(msgBlock)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions())
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]

	var prevOutScripts [][]byte
	for _, tx := range txs {
		for _, txIn := range tx.TxIn {
			prevOutScripts = append(prevOutScripts, c.scripts[txIn.PreviousOutPoint])
		}
	}
	filter, _, err := builder.BuildScriptFilter(msgBlock, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tx := range msgBlock.Transactions {
		hash := tx.TxHash()
		for i, txOut := range tx.TxOut {
			script := txOut.PkScript
			if !txOut.TokenData.IsEmpty() {
				prefix := txOut.TokenData.TokenDataBuffer()
				script = append(prefix.Bytes(), script...)
			}
			c.scripts[wire.OutPoint{Hash: hash, Index: uint32(i)}] = script
		}
	}

	c.mu.Lock()
	height := uint32(c.bestBlock.Height + 1)
	hash := msgBlock.Header.BlockHash()
	c.blockHeightIndex[hash] = height
	c.blockHashesByHeight[height] = &hash
	c.blockHeaders[hash] = &msgBlock.Header
	c.blocks[hash] = bchutil.NewBlock(msgBlock)
	c.filters[hash] = filter
	filterHeader, _ := builder.MakeHeaderForFilter(filter, *c.filterHeadersByHeight[height-1])
	c.filterHeadersByHeight[height] = &filterHeader
	c.bestBlock = waddrmgr.BlockStamp{
		Height: int32(height), Hash: hash, Timestamp: msgBlock.Header.Timestamp,
	}
	stamp := c.bestBlock
	c.mu.Unlock()
	return stamp
}

// reported keeps the transactions a rescan reports, by block height.
type reported struct {
	mu  sync.Mutex
	txs map[int32][]chainhash.Hash
}

func (r *reported) handlers() rpcclient.NotificationHandlers {
	r.txs = make(map[int32][]chainhash.Hash)
	return rpcclient.NotificationHandlers{
		OnFilteredBlockConnected: func(height int32, _ *wire.BlockHeader, txs []*bchutil.Tx) {
			r.mu.Lock()
			defer r.mu.Unlock()
			for _, tx := range txs {
				r.txs[height] = append(r.txs[height], *tx.Hash())
			}
		},
	}
}

// waitFor waits for the transactions to be reported at their heights.
func (r *reported) waitFor(t *testing.T, want map[int32][]chainhash.Hash) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.mu.Lock()
		got := true
		for height, txs := range want {
			for _, tx := range txs {
				got = got && slices.Contains(r.txs[height], tx)
			}
		}
		r.mu.Unlock()
		if got {
			return
		}
		if time.Now().After(deadline) {
			r.mu.Lock()
			defer r.mu.Unlock()
			t.Fatalf("reported %v, want %v", r.txs, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// categoryChain is a chain of script filters whose blocks hold a payment to
// a script, an output with tokens of a category, and the spends of both.
type categoryChain struct {
	*scriptRescanChain
	category                                     [32]byte
	script                                       []byte
	payment, tokens, spendPayment, spendTokens   *wire.MsgTx
	paymentAt, tokensAt, spentPaymentAt, spentAt int32
}

func newCategoryChain(t *testing.T) *categoryChain {
	t.Helper()
	c := &categoryChain{
		scriptRescanChain: newScriptRescanChain(t),
		category:          [32]byte{0xc4, 0x7e},
		script:            disputeScript(0x61),
	}
	funding := func(n byte) wire.OutPoint {
		return wire.OutPoint{Hash: chainhash.Hash{0xf0, n}}
	}
	c.scripts[funding(1)] = disputeScript(0x71)
	c.scripts[funding(2)] = disputeScript(0x72)

	// A rewind goes down to the block after a height above the genesis.
	c.addBlock(t)

	c.payment = wire.NewMsgTx(2)
	c.payment.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xf0, 1}}, nil))
	c.payment.AddTxOut(wire.NewTxOut(1000, c.script, wire.TokenData{}))
	c.paymentAt = c.addBlock(t, c.payment).Height

	c.tokens = wire.NewMsgTx(2)
	c.tokens.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{0xf0, 2}}, nil))
	c.tokens.AddTxOut(wire.NewTxOut(1000, disputeScript(0x62), wire.TokenData{
		CategoryID: c.category, Amount: 9, BitField: wire.HAS_AMOUNT,
	}))
	c.tokensAt = c.addBlock(t, c.tokens).Height
	c.addBlock(t)

	paymentHash, tokensHash := c.payment.TxHash(), c.tokens.TxHash()
	c.spendPayment = wire.NewMsgTx(2)
	c.spendPayment.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&paymentHash, 0), nil))
	c.spendPayment.AddTxOut(wire.NewTxOut(900, disputeScript(0x63), wire.TokenData{}))
	c.spentPaymentAt = c.addBlock(t, c.spendPayment).Height

	c.spendTokens = wire.NewMsgTx(2)
	c.spendTokens.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&tokensHash, 0), nil))
	c.spendTokens.AddTxOut(wire.NewTxOut(900, disputeScript(0x64), wire.TokenData{}))
	c.spentAt = c.addBlock(t, c.spendTokens).Height
	c.addBlock(t)
	return c
}

// TestScriptFilterRescanCategories checks a rescan on script filters end to
// end: one that watches a token category reports the transaction that
// creates an output with tokens of it, and then the one that spends that
// output, whose block the script filter matches by the category again.
func TestScriptFilterRescanCategories(t *testing.T) {
	c := newCategoryChain(t)
	var r reported
	genesis := c.blockStamp(0)
	tip := c.blockStamp(c.bestBlock.Height)
	err := rescan(c, NotificationHandlers(r.handlers()), StartBlock(&genesis),
		EndBlock(&tip), WatchCategories(c.category))
	if err != nil {
		t.Fatal(err)
	}
	r.waitFor(t, map[int32][]chainhash.Hash{
		c.tokensAt: {c.tokens.TxHash()},
		c.spentAt:  {c.spendTokens.TxHash()},
	})
	if len(r.txs) != 2 {
		t.Fatalf("reported %v, want the tokens and their spend only", r.txs)
	}
}

// TestScriptFilterRescanUpdate checks updates of a rescan on script filters
// end to end: once it has scanned the chain, adding an address, an input with
// its script, and a category, and rewinding, has it scan again and report the
// payment to the address and its spend, the spend of the input, and the
// tokens and their spend.
func TestScriptFilterRescanUpdate(t *testing.T) {
	c := newCategoryChain(t)
	var r reported
	quit := make(chan struct{})
	genesis := c.blockStamp(0)
	subscriptions := c.watchSubscriptions()
	rescan := NewRescan(c, NotificationHandlers(r.handlers()),
		StartBlock(&genesis), QuitChan(quit))
	errChan := rescan.Start()
	defer func() {
		close(quit)
		select {
		case err := <-errChan:
			if !errors.Is(err, ErrRescanExit) {
				t.Errorf("rescan ended with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("rescan didn't end")
		}
	}()

	// It has scanned the chain once it subscribes at the tip.
	select {
	case height := <-subscriptions:
		if int32(height) != c.bestBlock.Height {
			t.Fatalf("subscribed at height %d, want %d", height, c.bestBlock.Height)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the rescan didn't reach the tip")
	}
	r.mu.Lock()
	if len(r.txs) != 0 {
		t.Fatalf("reported %v while watching nothing", r.txs)
	}
	r.mu.Unlock()

	addr, err := bchutil.NewAddressPubKeyHash(c.script[3:23], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	paymentHash := c.payment.TxHash()
	input := InputWithScript{OutPoint: *wire.NewOutPoint(&paymentHash, 0), PkScript: c.script}
	err = rescan.Update(AddAddrs(addr), AddInputs(input), AddCategories(c.category),
		Rewind(1), DisableDisconnectedNtfns(true))
	if err != nil {
		t.Fatal(err)
	}
	r.waitFor(t, map[int32][]chainhash.Hash{
		c.paymentAt:      {c.payment.TxHash()},
		c.tokensAt:       {c.tokens.TxHash()},
		c.spentPaymentAt: {c.spendPayment.TxHash()},
		c.spentAt:        {c.spendTokens.TxHash()},
	})
}

// TestScriptFilterUpdateFilter checks what an update adds to the watch list
// of a rescan on script filters: the keys of the scripts of addresses and of
// inputs, and of categories, and no outpoint.
func TestScriptFilterUpdateFilter(t *testing.T) {
	c := newCategoryChain(t)
	ro := &rescanOptions{filterType: wire.GCSFilterScripts}
	addr, err := bchutil.NewAddressPubKeyHash(c.script[3:23], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	inputScript := disputeScript(0x66)
	stamp := c.blockStamp(c.bestBlock.Height)
	header := *c.blockHeaders[stamp.Hash]
	rewound, err := ro.updateFilter(c, &updateOptions{
		addrs:      []bchutil.Address{addr},
		inputs:     []InputWithScript{{OutPoint: wire.OutPoint{Index: 4}, PkScript: inputScript}},
		categories: [][32]byte{c.category},
		rewind:     uint32(c.tokensAt),
	}, &stamp, &header)
	if err != nil || !rewound {
		t.Fatalf("rewound %v, %v", rewound, err)
	}
	scriptKey, inputKey := builder.ScriptKey(c.script), builder.ScriptKey(inputScript)
	categoryKey := builder.CategoryKey(c.category)
	want := [][]byte{scriptKey[:], inputKey[:], categoryKey[:]}
	if !slices.EqualFunc(ro.watchList, want, bytes.Equal) {
		t.Errorf("watch list %x, want %x", ro.watchList, want)
	}
	if stamp.Height != c.tokensAt || stamp.Hash != c.blockStamp(c.tokensAt).Hash {
		t.Errorf("rewound to %d, want %d", stamp.Height, c.tokensAt)
	}
}

// TestScriptFilterInputsNeedScripts checks that an input watched on script
// filters without the script of the output it spends is refused, in a rescan,
// an update, GetUtxo, and a spend search, whose found can't return one
// either, and that on regular filters it is taken as before.  It also checks
// that categories added to a rescan on regular filters are refused by the
// update, before the rescan sees them.
func TestScriptFilterInputsNeedScripts(t *testing.T) {
	bare := InputWithScript{OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}}}

	scripts := newScriptRescanChain(t)
	if err := rescan(scripts, WatchInputs(bare)); !errors.Is(err, ErrInputNeedsScript) {
		t.Errorf("rescan: %v", err)
	}
	if err := NewRescan(scripts).Update(AddInputs(bare)); !errors.Is(err, ErrInputNeedsScript) {
		t.Errorf("update: %v", err)
	}
	if err := checkInputScripts(wire.GCSFilterRegular, []InputWithScript{bare}); err != nil {
		t.Errorf("regular filters: %v", err)
	}

	cs := &ChainService{chainParams: chaincfg.SimNetParams, filterType: wire.GCSFilterScripts}
	if _, err := cs.GetUtxo(WatchInputs(bare)); !errors.Is(err, ErrInputNeedsScript) {
		t.Errorf("GetUtxo: %v", err)
	}

	regular := newMockChainSource(1)
	if err := NewRescan(regular).Update(AddCategories([32]byte{1})); !errors.Is(err, ErrCategoriesNeedScriptFilters) {
		t.Errorf("categories on regular filters: %v", err)
	}

	// A spend search, and one whose found returns an input without its
	// script.
	spent := wire.OutPoint{Hash: chainhash.Hash{0x33}, Index: 1}
	script := disputeScript(0x44)
	chain := newScriptSearchChain(t, 4, map[int32][]*wire.MsgTx{
		2: {scriptTestTx(disputeScript(0x45), spent)},
	}, map[wire.OutPoint][]byte{spent: script})
	never := make(chan struct{})
	if _, err := searchScriptSpends(chain, []InputWithScript{bare}, 1, 4, nil, nil,
		never, never); !errors.Is(err, ErrInputNeedsScript) {
		t.Errorf("spend search: %v", err)
	}
	_, err := searchScriptSpends(chain, []InputWithScript{{OutPoint: spent, PkScript: script}},
		1, 4, func(FoundSpend) []InputWithScript { return []InputWithScript{bare} },
		nil, never, never)
	if !errors.Is(err, ErrInputNeedsScript) {
		t.Errorf("spend search whose found returns an input without its script: %v", err)
	}
}

// TestScriptFilterEntriesCached checks that the keys a spend reporter matches
// script filters with are hashed once while the watched outpoints stay the
// same, and again once they change.
func TestScriptFilterEntriesCached(t *testing.T) {
	b := newBatchSpendReporter()
	script := disputeScript(0x51)
	b.addNewRequests([]*GetUtxoRequest{
		{Input: &InputWithScript{OutPoint: wire.OutPoint{Index: 1}, PkScript: script}},
		{Input: &InputWithScript{OutPoint: wire.OutPoint{Index: 2}, PkScript: script}},
	})
	first := b.scriptFilterEntries()
	key := builder.ScriptKey(script)
	if len(first) != 1 || !bytes.Equal(first[0], key[:]) {
		t.Fatalf("entries %x, want the script's key once", first)
	}
	if again := b.scriptFilterEntries(); &again[0] != &first[0] {
		t.Error("the keys were hashed again while nothing changed")
	}

	other := disputeScript(0x52)
	b.addNewRequests([]*GetUtxoRequest{
		{Input: &InputWithScript{OutPoint: wire.OutPoint{Index: 3}, PkScript: other}},
	})
	if len(b.scriptFilterEntries()) != 2 {
		t.Errorf("entries %x after a new outpoint, want two keys", b.scriptFilterEntries())
	}
}
