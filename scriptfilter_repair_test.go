package neutrino

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/peer"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs/builder"
	"github.com/gcash/bchwallet/walletdb"
	"github.com/gcash/neutrino/banman"
	"github.com/gcash/neutrino/cache/lru"
	"github.com/gcash/neutrino/headerfs"
)

// scriptPeer is a peer of the end-to-end script filter tests: the entry tree
// it proves, and the filter chain it serves.
type scriptPeer struct {
	tree  *disputePeer
	chain *filterChain

	// served is the script filter it serves for the block in dispute, or
	// nil when it doesn't serve one.
	served []byte
}

// mockScriptPeers is a QueryAccess and a scriptTreeSource whose peers serve
// script filters: filter headers from their chains, the filter of the block
// in dispute, and the proofs and leaves of its entry tree.
type mockScriptPeers struct {
	blockHashes []chainhash.Hash
	heights     map[chainhash.Hash]uint32
	disputed    uint32
	peers       map[string]*scriptPeer
}

func (m *mockScriptPeers) queryAllPeers(msg wire.Message,
	checkResponse func(sp *ServerPeer, resp wire.Message,
		quit chan<- struct{}, peerQuit chan<- struct{}),
	_ ...QueryOption) {

	for addr, p := range m.peers {
		var resp wire.Message
		switch msg := msg.(type) {
		case *wire.MsgGetCFHeaders:
			headers := wire.NewMsgCFHeaders()
			headers.FilterType = msg.FilterType
			headers.StopHash = msg.StopHash
			headers.PrevFilterHeader = p.chain.headers[msg.StartHeight-1]
			for height := msg.StartHeight; height <= m.heights[msg.StopHash]; height++ {
				_ = headers.AddCFHash(&p.chain.hashes[height])
			}
			resp = headers

		case *wire.MsgGetCFilters:
			if msg.StartHeight != m.disputed || p.served == nil {
				continue
			}
			resp = wire.NewMsgCFilter(
				msg.FilterType, &m.blockHashes[msg.StartHeight], p.served,
			)

		default:
			continue
		}

		pp, err := peer.NewOutboundPeer(&peer.Config{}, addr)
		if err != nil {
			panic(err)
		}
		checkResponse(&ServerPeer{Peer: pp}, resp, make(chan struct{}),
			make(chan struct{}))
	}
}

func (m *mockScriptPeers) fetchScriptProof(addr string, _ chainhash.Hash,
	index uint32, _ <-chan struct{}) (*wire.MsgCFProof, error) {

	return m.peers[addr].tree.answer(index)
}

func (m *mockScriptPeers) fetchScriptRange(addr string, _ chainhash.Hash,
	bits uint16, prefix [32]byte, _ <-chan struct{}) (*wire.MsgCFRange, error) {

	return m.peers[addr].tree.answerRange(bits, prefix)
}

var _ QueryAccess = (*mockScriptPeers)(nil)
var _ scriptTreeSource = (*mockScriptPeers)(nil)

// scriptRepairTest is a block manager that syncs script filters, whose block
// headers run to tip and hold the blocks of a dispute chain: the block in
// dispute at its height, and the older block whose outputs it spends at its
// own.
type scriptRepairTest struct {
	bm          *blockManager
	store       *headerfs.FilterHeaderStore
	chain       *disputeChain
	peers       *mockScriptPeers
	blockHashes []chainhash.Hash
	hashes      []chainhash.Hash
	genesis     chainhash.Hash
	tip         uint32
}

// setupScriptRepairTest sets up a scriptRepairTest with no peers and no
// filter headers stored.
func setupScriptRepairTest(t *testing.T) *scriptRepairTest {
	t.Helper()

	// The header stores keep their files open, which Windows doesn't let
	// a test's own temporary directory remove.
	tempDir, err := os.MkdirTemp("", "neutrino")
	if err != nil {
		t.Fatal(err)
	}
	db, err := walletdb.Create("bdb", tempDir+"/weks.db", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(tempDir)
	})
	params := chaincfg.SimNetParams
	hdrStore, err := headerfs.NewBlockHeaderStore(tempDir, db, &params)
	if err != nil {
		t.Fatal(err)
	}
	store, err := headerfs.NewFilterHeaderStore(
		tempDir, db, headerfs.ScriptFilter, &params, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	banStore, err := banman.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	cs := &ChainService{
		chainParams:         params,
		BlockHeaders:        hdrStore,
		ScriptFilterHeaders: store,
		filterHeaders:       store,
		filterType:          wire.GCSFilterScripts,
		banStore:            banStore,
		FilterCache:         lru.NewCache(1 << 20),
		FilterDB:            newTestFilterDB(t),
		timeSource:          blockchain.NewMedianTime(),
	}
	bm, err := newBlockManager(cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs.blockManager = bm

	// Looking up the peers to disconnect returns right away once the
	// ChainService quits.
	cs.quit = make(chan struct{})
	close(cs.quit)

	c := newDisputeChain(t)
	tip := c.block.height + 3
	byHeight := make(map[uint32]*wire.BlockHeader)
	for _, block := range c.blocks {
		byHeight[block.height] = &block.header
	}
	genesis, _, err := hdrStore.ChainTip()
	if err != nil {
		t.Fatal(err)
	}
	blockHashes := []chainhash.Hash{genesis.BlockHash()}
	heights := map[chainhash.Hash]uint32{blockHashes[0]: 0}
	var blockHeaders []headerfs.BlockHeader
	for height := uint32(1); height <= tip; height++ {
		header, ok := byHeight[height]
		if !ok {
			header = &wire.BlockHeader{
				PrevBlock: blockHashes[height-1],
				Timestamp: time.Unix(time.Now().Unix(), 0),
				Nonce:     height,
			}
		}
		blockHashes = append(blockHashes, header.BlockHash())
		heights[blockHashes[height]] = height
		blockHeaders = append(blockHeaders, headerfs.BlockHeader{
			BlockHeader: header, Height: height,
		})
	}
	if err := hdrStore.WriteHeaders(blockHeaders...); err != nil {
		t.Fatal(err)
	}
	bm.headerTip = tip
	bm.headerTipHash = blockHashes[tip]

	genesisFilterHeader, err := store.FetchHeaderByHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]chainhash.Hash, tip+1)
	for height := range hashes {
		hashes[height] = chainhash.HashH([]byte{byte(height), 0x5c})
	}

	peers := &mockScriptPeers{
		blockHashes: blockHashes,
		heights:     heights,
		disputed:    c.block.height,
		peers:       make(map[string]*scriptPeer),
	}
	bm.queries = peers
	bm.scriptTrees = peers

	return &scriptRepairTest{
		bm:          bm,
		store:       store,
		chain:       c,
		peers:       peers,
		blockHashes: blockHashes,
		hashes:      hashes,
		genesis:     *genesisFilterHeader,
		tip:         tip,
	}
}

// addPeer adds a peer that proves the given tree and serves its filter, and
// the filter chain with that filter's hash at the block in dispute.
func (rt *scriptRepairTest) addPeer(t *testing.T, addr string, tree *disputePeer) *scriptPeer {
	t.Helper()
	served := tree.servedFilter(t)
	filter := append(served.root[:], served.filter...)
	hashes := slices.Clone(rt.hashes)
	hashes[rt.chain.block.height] = chainhash.DoubleHashH(filter)
	p := &scriptPeer{
		tree:   tree,
		chain:  newFilterChain(rt.genesis, hashes, nil),
		served: filter,
	}
	rt.peers.peers[addr] = p
	return p
}

// claims returns each peer's filter hash at the block in dispute.
func (rt *scriptRepairTest) claims() map[string]chainhash.Hash {
	claims := make(map[string]chainhash.Hash)
	for addr, p := range rt.peers.peers {
		claims[addr] = p.chain.hashes[rt.chain.block.height]
	}
	return claims
}

// assertBanned asserts that exactly the given peers are banned.
func (rt *scriptRepairTest) assertBanned(t *testing.T, banned ...string) {
	t.Helper()
	for addr := range rt.peers.peers {
		if got, want := rt.bm.server.IsBanned(addr), slices.Contains(banned, addr); got != want {
			t.Errorf("peer %v banned %v, want %v", addr, got, want)
		}
	}
}

// omitLeaf is a liar's tree: the true one without a leaf.
func omitLeaf(c *disputeChain) *disputePeer {
	return c.liar(true, func(l []builder.ScriptLeaf) []builder.ScriptLeaf {
		return slices.Delete(l, 3, 4)
	})
}

// TestDetectBadScriptPeers checks end to end, from the filter hashes peers
// announce for a block, that the peers serving a wrong script filter are
// found by their proofs and leaves, and that a dispute in which a peer that
// announced another filter didn't answer is not settled, and blames no one.
func TestDetectBadScriptPeers(t *testing.T) {
	tests := []struct {
		name string

		// peers holds what each peer serves: "honest", "wrongTree",
		// "otherTree", "wrongFilter", or with "-silent" one that
		// doesn't prove it, "-noFilter" one that doesn't serve its
		// filter, or "-garbled" one that serves bytes that don't parse.
		peers   map[string]string
		wantBad []string
		wantErr bool
	}{{
		name:    "a wrong tree",
		peers:   map[string]string{repairPeer1: "honest", repairPeer2: "wrongTree"},
		wantBad: []string{repairPeer2},
	}, {
		name: "a wrong filter under the true root",
		peers: map[string]string{
			repairPeer1: "honest", repairPeer2: "honest", repairPeer3: "wrongFilter",
		},
		wantBad: []string{repairPeer3},
	}, {
		name: "a filter that doesn't parse",
		peers: map[string]string{
			repairPeer1: "honest", repairPeer2: "honest-garbled",
		},
		wantBad: []string{repairPeer2},
	}, {
		name:    "an honest peer that doesn't prove its filter",
		peers:   map[string]string{repairPeer1: "honest-silent", repairPeer2: "wrongTree"},
		wantErr: true,
	}, {
		name:    "an honest peer that doesn't serve its filter",
		peers:   map[string]string{repairPeer1: "honest-noFilter", repairPeer2: "wrongTree"},
		wantErr: true,
	}, {
		name: "a liar that doesn't prove its filter",
		peers: map[string]string{
			repairPeer1: "honest", repairPeer2: "honest",
			repairPeer3: "wrongTree-silent",
		},
		wantErr: true,
	}, {
		name: "a wrong filter shown by another peer's leaves",
		peers: map[string]string{
			repairPeer1: "honest", repairPeer2: "wrongTree",
			repairPeer3: "wrongFilter-silent",
		},
		wantBad: []string{repairPeer2, repairPeer3},
	}, {
		name: "a liar found while another peer doesn't answer",
		peers: map[string]string{
			repairPeer1: "honest", repairPeer2: "wrongTree",
			repairPeer3: "otherTree-silent",
		},
		wantBad: []string{repairPeer2},
		wantErr: true,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := setupScriptRepairTest(t)
			c := rt.chain
			for addr, kind := range test.peers {
				var tree *disputePeer
				base, mode, _ := strings.Cut(kind, "-")
				switch base {
				case "honest":
					tree = c.honest()
				case "wrongTree":
					tree = omitLeaf(c)
				case "otherTree":
					tree = c.liar(true, func(l []builder.ScriptLeaf) []builder.ScriptLeaf {
						return l[1:]
					})
				case "wrongFilter":
					tree = c.honest()
					tree.filter = []byte{0x00}
				}
				p := rt.addPeer(t, addr, tree)
				switch mode {
				case "silent":
					tree.silent = true
				case "noFilter":
					p.served = nil
				case "garbled":
					p.served = p.served[:chainhash.HashSize-1]
				}
			}

			header := &c.block.header
			bad, err := rt.bm.detectBadScriptPeers(header, c.block.height, rt.claims())
			if (err != nil) != test.wantErr {
				t.Fatalf("error %v, want one %v", err, test.wantErr)
			}
			if err != nil && !errors.Is(err, errScriptDisputeUnsettled) {
				t.Fatalf("error %v isn't an unsettled dispute", err)
			}
			if err != nil {
				// The peers found at fault are banned with the
				// error, and no one else.
				rt.assertBanned(t, test.wantBad...)
				return
			}
			slices.Sort(bad)
			if !slices.Equal(bad, test.wantBad) {
				t.Fatalf("at fault %v, want %v", bad, test.wantBad)
			}
		})
	}
}

// TestScriptFilterHeaderOfPeers checks end to end that the filter header the
// peers back for a block is the one of its true script filter, and that none
// is given while a peer that announced another doesn't answer.
func TestScriptFilterHeaderOfPeers(t *testing.T) {
	rt := setupScriptRepairTest(t)
	c := rt.chain
	honest := rt.addPeer(t, repairPeer1, c.honest())
	rt.addPeer(t, repairPeer2, omitLeaf(c))
	height := c.block.height
	claims := make(map[string]chainhash.Hash)
	for addr, p := range rt.peers.peers {
		claims[addr] = p.chain.headers[height]
	}
	prev := honest.chain.headers[height-1]

	got, err := rt.bm.scriptFilterHeaderOfPeers(&c.block.header, height, prev, claims)
	if err != nil || got != honest.chain.headers[height] {
		t.Fatalf("header %v, %v; want %v", got, err, honest.chain.headers[height])
	}

	honest.tree.silent = true
	if _, err := rt.bm.scriptFilterHeaderOfPeers(&c.block.header, height, prev, claims); !errors.Is(err, errScriptDisputeUnsettled) {
		t.Fatalf("with the honest peer silent: %v", err)
	}
}

// TestRepairScriptFilterHeaders checks end to end that a repair of script
// filter headers settles a disagreement at a block by the peers' proofs: it
// bans the peer that serves a wrong filter, rolls our headers back when they
// are the wrong ones, and does neither, returning an error, when the peer
// that could show who is right doesn't answer.
func TestRepairScriptFilterHeaders(t *testing.T) {
	tests := []struct {
		name         string
		storeHonest  bool
		honestSilent bool
		wantErr      bool
		wantRollback bool
		wantBanned   []string
	}{
		{name: "a peer serving a wrong filter", storeHonest: true,
			wantBanned: []string{repairPeer2}},
		{name: "our filter headers are wrong", storeHonest: false,
			wantRollback: true, wantBanned: []string{repairPeer2}},
		{name: "the honest peer doesn't answer", storeHonest: true,
			honestSilent: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := setupScriptRepairTest(t)
			c := rt.chain
			honest := rt.addPeer(t, repairPeer1, c.honest())
			liar := rt.addPeer(t, repairPeer2, omitLeaf(c))
			honest.tree.silent = test.honestSilent

			stored := liar.chain
			if test.storeHonest {
				stored = honest.chain
			}
			var headers []headerfs.FilterHeader
			for height := uint32(1); height <= rt.tip; height++ {
				headers = append(headers, headerfs.FilterHeader{
					HeaderHash: rt.blockHashes[height],
					FilterHash: stored.headers[height],
					Height:     height,
				})
			}
			if err := rt.store.WriteHeaders(headers...); err != nil {
				t.Fatal(err)
			}
			rt.bm.filterHeaderTip = rt.tip
			rt.bm.filterHeaderTipHash = rt.blockHashes[rt.tip]

			err := rt.bm.repairFilterHeaders()
			if (err != nil) != test.wantErr {
				t.Fatalf("error %v, want one %v", err, test.wantErr)
			}
			rt.assertBanned(t, test.wantBanned...)

			want := rt.tip
			if test.wantRollback {
				want = c.block.height - 1
			}
			header, height, err := rt.store.ChainTip()
			if err != nil || height != want || *header != stored.headers[want] {
				t.Fatalf("filter tip at height %d, %v; want %d", height, err, want)
			}
		})
	}
}
