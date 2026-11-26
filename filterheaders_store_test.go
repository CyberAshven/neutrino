package neutrino

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchwallet/walletdb"
	"github.com/gcash/neutrino/headerfs"
)

// headerStoresDir returns a data directory with a database, and removes it
// once the test ends, as far as it can.
func headerStoresDir(t *testing.T) (string, walletdb.DB) {
	t.Helper()
	dir, err := os.MkdirTemp("", "neutrino")
	if err != nil {
		t.Fatal(err)
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "neutrino.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	})
	return dir, db
}

// writeTestChain writes n block headers after the genesis block, and the
// filter headers of the first of them to each filter store given, and
// returns the block hashes by height.
func writeTestChain(t *testing.T, blocks headerfs.BlockHeaderStore, n uint32,
	filters map[*headerfs.FilterHeaderStore]uint32) []chainhash.Hash {

	t.Helper()
	genesis, _, err := blocks.ChainTip()
	if err != nil {
		t.Fatal(err)
	}
	hashes := []chainhash.Hash{genesis.BlockHash()}
	var headers []headerfs.BlockHeader
	for h := uint32(1); h <= n; h++ {
		header := &wire.BlockHeader{
			PrevBlock: hashes[h-1],
			Timestamp: time.Unix(time.Now().Unix(), 0),
			Nonce:     h,
		}
		hashes = append(hashes, header.BlockHash())
		headers = append(headers, headerfs.BlockHeader{BlockHeader: header, Height: h})
	}
	if err := blocks.WriteHeaders(headers...); err != nil {
		t.Fatal(err)
	}
	for store, tip := range filters {
		var filterHeaders []headerfs.FilterHeader
		for h := uint32(1); h <= tip; h++ {
			filterHeaders = append(filterHeaders, headerfs.FilterHeader{
				HeaderHash: hashes[h],
				FilterHash: chainhash.HashH([]byte{byte(h), byte(tip)}),
				Height:     h,
			})
		}
		if err := store.WriteHeaders(filterHeaders...); err != nil {
			t.Fatal(err)
		}
	}
	return hashes
}

// TestRollBackOtherFilterHeaders checks that a reorg rolls back the filter
// headers of the type a service doesn't sync too, which share the index of
// the blocks, so that a service that syncs that type opens them again at the
// block the chain went back to.
func TestRollBackOtherFilterHeaders(t *testing.T) {
	dir, db := headerStoresDir(t)
	params := chaincfg.SimNetParams
	blocks, err := headerfs.NewBlockHeaderStore(dir, db, &params)
	if err != nil {
		t.Fatal(err)
	}
	regular, err := headerfs.NewFilterHeaderStore(dir, db, headerfs.RegularFilter, &params, nil)
	if err != nil {
		t.Fatal(err)
	}
	script, err := headerfs.NewFilterHeaderStore(dir, db, headerfs.ScriptFilter, &params, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestChain(t, blocks, 10, map[*headerfs.FilterHeaderStore]uint32{regular: 10, script: 8})
	want, err := script.FetchHeaderByHeight(5)
	if err != nil {
		t.Fatal(err)
	}
	if err := script.Close(); err != nil {
		t.Fatal(err)
	}

	cs := &ChainService{
		chainParams:      params,
		BlockHeaders:     blocks,
		RegFilterHeaders: regular,
		filterHeaders:    regular,
		filterType:       wire.GCSFilterRegular,
		dataDir:          dir,
		db:               db,
	}
	bm, err := newBlockManager(cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs.blockManager = bm
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-bm.Notifications():
			case <-done:
				return
			}
		}
	}()
	if _, err := cs.rollBackToHeight(5); err != nil {
		t.Fatal(err)
	}

	script, err = headerfs.NewFilterHeaderStore(dir, db, headerfs.ScriptFilter, &params, nil)
	if err != nil {
		t.Fatalf("the script filter headers don't open after the reorg: %v", err)
	}
	defer func() { _ = script.Close() }()
	tip, height, err := script.ChainTip()
	if err != nil || height != 5 || *tip != *want {
		t.Fatalf("script filter tip %v at height %d, %v; want %v at 5", tip, height, err, want)
	}
}

// openFiles returns how many files the process has open, or -1 where that
// can't be told.
func openFiles() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// TestNewChainServiceClosesFiles checks that NewChainService closes the
// header files it opened when it fails: when the filter type is unknown,
// after the block headers were opened, when the block headers have no index,
// and when the filter headers' tip is not in the index, as a reorg left it
// before their rollback was fixed.
// Where the open files can't be counted, as on Windows, the files must be
// removable, which an open file isn't there.
func TestNewChainServiceClosesFiles(t *testing.T) {
	params := chaincfg.SimNetParams
	for name, prepare := range map[string]func(t *testing.T, dir string, db walletdb.DB) wire.FilterType{
		"an unknown filter type": func(*testing.T, string, walletdb.DB) wire.FilterType {
			return wire.FilterType(9)
		},
		"block headers without an index": func(t *testing.T, dir string, _ walletdb.DB) wire.FilterType {
			header := make([]byte, 80)
			if err := os.WriteFile(filepath.Join(dir, "block_headers.bin"), header, 0644); err != nil {
				t.Fatal(err)
			}
			return wire.GCSFilterScripts
		},
		"filter headers whose tip left the index": func(t *testing.T, dir string, db walletdb.DB) wire.FilterType {
			blocks, err := headerfs.NewBlockHeaderStore(dir, db, &params)
			if err != nil {
				t.Fatal(err)
			}
			script, err := headerfs.NewFilterHeaderStore(dir, db, headerfs.ScriptFilter, &params, nil)
			if err != nil {
				t.Fatal(err)
			}
			writeTestChain(t, blocks, 5, map[*headerfs.FilterHeaderStore]uint32{script: 5})
			for i := 0; i < 2; i++ {
				if _, err := blocks.RollbackLastBlock(); err != nil {
					t.Fatal(err)
				}
			}
			_ = blocks.(interface{ Close() error }).Close()
			_ = script.Close()
			return wire.GCSFilterScripts
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, db := headerStoresDir(t)
			fType := prepare(t, dir, db)
			before := openFiles()
			_, err := NewChainService(Config{
				DataDir:     dir,
				Database:    db,
				ChainParams: params,
				FilterType:  fType,
			})
			if err == nil {
				t.Fatal("the service was made")
			}
			if before >= 0 {
				if after := openFiles(); after != before {
					t.Fatalf("%d files open after a failed start, %d before", after, before)
				}
				return
			}
			for _, file := range []string{"block_headers.bin", "script_filter_headers.bin"} {
				err := os.Remove(filepath.Join(dir, file))
				if err != nil && !os.IsNotExist(err) {
					t.Errorf("%s stays open: %v", file, err)
				}
			}
		})
	}
}
