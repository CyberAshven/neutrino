package neutrino

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestBanScoreMirrorTryTake checks that a take whose score plus room equals
// the max is counted and one past it is not, that a room larger than the add
// reserves the later request, and that concurrent takes never read a score
// above the max.
func TestBanScoreMirrorTryTake(t *testing.T) {
	// The points already there are persistent, so they do not decay out
	// from under the check.  The add itself is transient and loses less
	// than one in the second a call can cross.
	var atMax banScoreMirror
	atMax.score.Increase(80, 0)
	if !atMax.tryTake(10, 10, 90) {
		t.Fatal("a score plus room equal to the max was not taken")
	}
	if got := atMax.Int(); got != 90 && got != 89 {
		t.Fatalf("score %d after taking the last room, want 90, or 89 a "+
			"second later", got)
	}

	var over banScoreMirror
	over.score.Increase(81, 0)
	if over.tryTake(10, 10, 90) {
		t.Fatal("a score plus room one over the max was taken")
	}
	if got := over.Int(); got != 81 {
		t.Fatalf("score %d after a refused take, want 81", got)
	}

	// 70 plus the add would fit in 90.  70 plus the room does not, so
	// nothing is counted.
	var wide banScoreMirror
	wide.score.Increase(70, 0)
	if wide.tryTake(10, 30, 90) {
		t.Fatal("a take whose room passes the max was taken")
	}
	if got := wide.Int(); got != 70 {
		t.Fatalf("score %d after a refused take, want 70", got)
	}

	// The same room fits from 50, and only the add is counted.
	var fits banScoreMirror
	fits.score.Increase(50, 0)
	if !fits.tryTake(10, 30, 90) {
		t.Fatal("a take whose room is larger than the add, and that " +
			"still fits, was not taken")
	}
	if got := fits.Int(); got != 60 && got != 59 {
		t.Fatalf("score %d after adding 10 under a room of 30, want "+
			"60, or 59 a second later", got)
	}

	// Persistent 0, and nothing transient yet, so nothing is decaying
	// until the takes below add to the transient part.  That part decays
	// by whole seconds, so a run that crosses a second can succeed more
	// than 90/5 times.  It cannot read above 90.
	var concurrent banScoreMirror
	const n = 50
	start := make(chan struct{})
	ready := make(chan struct{}, n)
	var wg sync.WaitGroup
	var successes atomic.Uint32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			if !concurrent.tryTake(5, 5, 90) {
				return
			}
			if got := concurrent.Int(); got > 90 {
				t.Errorf("score %d is over 90 after a take", got)
			}
			successes.Add(1)
		}()
	}
	for i := 0; i < n; i++ {
		<-ready
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got < 18 {
		t.Fatalf("%d takes succeeded, want at least 18", got)
	}
	if got := concurrent.Int(); got > 90 {
		t.Fatalf("score %d is over 90", got)
	}
}

// TestBanScoreMirrorReserve checks that room held for a later request can't
// be taken by other requests, and is counted when claimed and free again when
// released.
func TestBanScoreMirrorReserve(t *testing.T) {
	var m banScoreMirror
	m.score.Increase(80, 0)
	if !m.tryReserve(2, 5, 90) {
		t.Fatal("a reservation that fits was refused")
	}
	taken := 0
	for m.tryTake(1, 1, 90) {
		taken++
	}
	if taken != 3 {
		t.Fatalf("%d takes fit beside the room held, want 3", taken)
	}
	m.claim(5)
	if got := m.Int(); got < 89 || got > 90 {
		t.Fatalf("score %d after the room held is claimed, want 90", got)
	}

	var r banScoreMirror
	r.score.Increase(80, 0)
	if !r.tryReserve(0, 10, 90) || r.tryTake(1, 1, 90) {
		t.Fatal("a take used room held")
	}
	r.release(10)
	if !r.tryTake(1, 1, 90) {
		t.Fatal("room released was not free")
	}
}
