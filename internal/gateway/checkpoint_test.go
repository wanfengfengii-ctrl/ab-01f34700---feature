package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

// cpDigest returns the cumulative contiguous byte count and lowercase hex
// SHA-256 over payload(0)..payload(lastSeq).
func cpDigest(t *testing.T, lastSeq int) (uint64, string) {
	t.Helper()
	h := sha256.New()
	var n uint64
	for s := 0; s <= lastSeq; s++ {
		p := payload(s)
		h.Write(p)
		n += uint64(len(p))
	}
	return n, hex.EncodeToString(h.Sum(nil))
}

func mustPlan(t *testing.T, seqs ...int) []Checkpoint {
	t.Helper()
	cps := make([]Checkpoint, len(seqs))
	for i, s := range seqs {
		n, sum := cpDigest(t, s)
		cps[i] = Checkpoint{Sequence: uint32(s), ContiguousBytes: n, SHA256: sum}
	}
	return cps
}

func TestValidateCheckpoints(t *testing.T) {
	good := Checkpoint{Sequence: 1, ContiguousBytes: 10, SHA256: strings.Repeat("a", 64)}
	cases := []struct {
		name string
		cps  []Checkpoint
	}{
		{"empty", nil},
		{"five entries", []Checkpoint{good, good, good, good, good}},
		{"zero bytes", []Checkpoint{{Sequence: 0, ContiguousBytes: 0, SHA256: strings.Repeat("a", 64)}}},
		{"non-increasing sequence", []Checkpoint{
			{Sequence: 5, ContiguousBytes: 10, SHA256: strings.Repeat("a", 64)},
			{Sequence: 5, ContiguousBytes: 20, SHA256: strings.Repeat("b", 64)},
		}},
		{"non-increasing bytes", []Checkpoint{
			{Sequence: 5, ContiguousBytes: 20, SHA256: strings.Repeat("a", 64)},
			{Sequence: 6, ContiguousBytes: 20, SHA256: strings.Repeat("b", 64)},
		}},
		{"uppercase hex", []Checkpoint{{Sequence: 1, ContiguousBytes: 10, SHA256: strings.Repeat("A", 64)}}},
		{"short hex", []Checkpoint{{Sequence: 1, ContiguousBytes: 10, SHA256: strings.Repeat("a", 63)}}},
		{"non-hex", []Checkpoint{{Sequence: 1, ContiguousBytes: 10, SHA256: strings.Repeat("g", 64)}}},
	}
	for _, tc := range cases {
		if reason := ValidateCheckpoints(tc.cps); reason == "" {
			t.Errorf("%s: expected validation error, got none", tc.name)
		}
	}
	if reason := ValidateCheckpoints([]Checkpoint{
		{Sequence: 0, ContiguousBytes: 5, SHA256: strings.Repeat("a", 64)},
		{Sequence: 3, ContiguousBytes: 9, SHA256: strings.Repeat("b", 64)},
	}); reason != "" {
		t.Errorf("valid plan rejected: %s", reason)
	}
}

func TestCheckpointRegisterAtCurrentNext(t *testing.T) {
	c := NewChannel(1)
	// First boundary at sequence 0: registration with next==0 is legal.
	created, err := c.RegisterPlan(mustPlan(t, 0))
	if err != nil || !created {
		t.Fatalf("register: created=%v err=%v", created, err)
	}
	feedSeqs(c, 0)
	st := c.Status()
	if st.Status != "ok" {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
	if st.CheckpointPlan == nil || st.CheckpointPlan.Checkpoints[0].State != cpMatched {
		t.Fatalf("checkpoint not matched: %+v", st.CheckpointPlan)
	}
}

func TestCheckpointRejectedAfterBoundaryCrossed(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0, 1) // next is now 2
	if _, err := c.RegisterPlan(mustPlan(t, 1)); err != ErrBoundaryCrossed {
		t.Fatalf("err=%v, want ErrBoundaryCrossed", err)
	}
	// Rejection leaves no plan behind.
	if c.HasPlan() {
		t.Fatal("rejected plan must not be stored")
	}
	// Boundary exactly at next (not yet consumed) is still acceptable.
	if _, err := c.RegisterPlan(mustPlan(t, 2)); err != nil {
		t.Fatalf("register at current next: %v", err)
	}
}

func TestCheckpointRetryIdenticalReturnsState(t *testing.T) {
	c := NewChannel(1)
	plan := mustPlan(t, 2)
	if created, err := c.RegisterPlan(plan); err != nil || !created {
		t.Fatalf("first register: created=%v err=%v", created, err)
	}
	feedSeqs(c, 0, 1, 2)
	created, err := c.RegisterPlan(plan)
	if err != nil || created {
		t.Fatalf("identical retry: created=%v err=%v", created, err)
	}
	st := c.PlanStatus()
	if len(st.Checkpoints) != 1 || st.Checkpoints[0].State != cpMatched {
		t.Fatalf("retry state: %+v", st)
	}
}

func TestCheckpointDifferentPlanConflicts(t *testing.T) {
	c := NewChannel(1)
	if _, err := c.RegisterPlan(mustPlan(t, 2)); err != nil {
		t.Fatal(err)
	}
	other := []Checkpoint{{Sequence: 2, ContiguousBytes: 1, SHA256: strings.Repeat("0", 64)}}
	if _, err := c.RegisterPlan(other); err != ErrPlanConflict {
		t.Fatalf("err=%v, want ErrPlanConflict", err)
	}
}

func TestCheckpointRejectedOnFailedChannel(t *testing.T) {
	c := NewChannel(1)
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("a")})
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("b")})
	if _, err := c.RegisterPlan(mustPlan(t, 0)); err != ErrChannelFailed {
		t.Fatalf("err=%v, want ErrChannelFailed", err)
	}
}

func TestCheckpointsMatchedOutOfOrder(t *testing.T) {
	c := NewChannel(1)
	if _, err := c.RegisterPlan(mustPlan(t, 1, 4, 9)); err != nil {
		t.Fatal(err)
	}
	// Deliver everything fully reversed, like the window test.
	for i := 9; i >= 0; i-- {
		feedSeqs(c, i)
	}
	st := c.Status()
	if st.Status != "ok" || st.NextSequence != 10 {
		t.Fatalf("status=%q next=%d reason=%q", st.Status, st.NextSequence, st.FailReason)
	}
	if st.CheckpointPlan == nil {
		t.Fatal("missing checkpointPlan in status")
	}
	for i, seq := range []uint32{1, 4, 9} {
		cp := st.CheckpointPlan.Checkpoints[i]
		if cp.Sequence != seq || cp.State != cpMatched {
			t.Fatalf("checkpoint %d: %+v", i, cp)
		}
	}
}

func TestCheckpointExcludesHigherBufferedFrames(t *testing.T) {
	c := NewChannel(1)
	// Boundary at sequence 2; frames 3 and beyond may already be buffered.
	if _, err := c.RegisterPlan(mustPlan(t, 2)); err != nil {
		t.Fatal(err)
	}
	feedSeqs(c, 4, 3) // buffered ahead of a hole
	feedSeqs(c, 0)    // drains 0 only; 1 still missing
	feedSeqs(c, 2, 1) // now 0..4 drain back-to-back
	st := c.Status()
	if st.Status != "ok" {
		t.Fatalf("status=%q reason=%q — buffered frame 3/4 leaked into boundary digest",
			st.Status, st.FailReason)
	}
	if got := st.CheckpointPlan.Checkpoints[0]; got.State != cpMatched {
		t.Fatalf("boundary state=%s", got.State)
	}
	if st.NextSequence != 5 || st.SHA256 != digestOf(0, 1, 2, 3, 4) {
		t.Fatalf("next=%d sha=%s", st.NextSequence, st.SHA256)
	}
}

func TestCheckpointPendingStaysPendingBeforeBoundary(t *testing.T) {
	c := NewChannel(1)
	if _, err := c.RegisterPlan(mustPlan(t, 3)); err != nil {
		t.Fatal(err)
	}
	feedSeqs(c, 0, 1, 3) // gap at 2: boundary sequence 3 not consumed
	if got := c.PlanStatus().Checkpoints[0]; got.State != cpPending {
		t.Fatalf("state=%s, want pending", got.State)
	}
	feedSeqs(c, 2)
	if got := c.PlanStatus().Checkpoints[0]; got.State != cpMatched {
		t.Fatalf("state=%s, want matched", got.State)
	}
}

func TestCheckpointMismatchFailsPermanently(t *testing.T) {
	c := NewChannel(1)
	plan := []Checkpoint{
		{Sequence: 1, ContiguousBytes: 999, SHA256: strings.Repeat("0", 64)},
		{Sequence: 4, ContiguousBytes: 2000, SHA256: strings.Repeat("1", 64)}, // stays pending
	}
	if _, err := c.RegisterPlan(plan); err != nil {
		t.Fatal(err)
	}
	feedSeqs(c, 0, 1, 2) // mismatch crossing sequence 1; frame 2 must not change state
	wantBytes, wantSHA := cpDigest(t, 1)
	st := c.Status()
	if st.Status != "failed" {
		t.Fatalf("status=%q, want failed", st.Status)
	}
	if !strings.Contains(st.FailReason, "checkpoint mismatch") ||
		!strings.Contains(st.FailReason, "sequence 1") {
		t.Fatalf("failReason=%q", st.FailReason)
	}
	if st.NextSequence != 2 {
		t.Fatalf("next=%d, want 2 (frozen at boundary)", st.NextSequence)
	}
	cps := st.CheckpointPlan.Checkpoints
	if cps[0].State != cpMismatch {
		t.Fatalf("entry0 state=%s", cps[0].State)
	}
	if cps[0].SHA256 != strings.Repeat("0", 64) || cps[0].ContiguousBytes != 999 {
		t.Fatalf("entry0 expectation mutated: %+v", cps[0])
	}
	if cps[0].ActualSHA256 != wantSHA || cps[0].ActualContiguousBytes != wantBytes {
		t.Fatalf("actual result: bytes=%d sha=%s, want bytes=%d sha=%s",
			cps[0].ActualContiguousBytes, cps[0].ActualSHA256, wantBytes, wantSHA)
	}
	if cps[1].State != cpPending {
		t.Fatalf("entry1 state=%s, want pending", cps[1].State)
	}
	before := c.Status()
	feedSeqs(c, 3, 4) // later frames, valid and retransmitted
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: payload(0)})
	after := c.Status()
	if after.Status != "failed" || after.FailReason != before.FailReason ||
		after.NextSequence != before.NextSequence || after.SHA256 != before.SHA256 ||
		after.ContiguousBytes != before.ContiguousBytes {
		t.Fatalf("state not frozen after checkpoint failure:\nbefore=%+v\nafter=%+v", before, after)
	}
	if got := after.CheckpointPlan.Checkpoints[0]; got.State != cpMismatch ||
		got.ActualSHA256 != wantSHA {
		t.Fatalf("mismatch detail not stable: %+v", got)
	}
}

func TestCheckpointStatusOmittedWithoutPlan(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0)
	if st := c.Status(); st.CheckpointPlan != nil {
		t.Fatalf("unregistered channel must not expose a plan: %+v", st.CheckpointPlan)
	}
}

// TestCheckpointRegistrationAtomicWithIngest exercises the atomic verdict
// against concurrent TCP ingest: either ingest already crossed the first
// boundary (whole plan rejected, no plan stored) or the plan was registered
// in time and every boundary of a correct stream is enforced.
func TestCheckpointRegistrationAtomicWithIngest(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		c := NewChannel(uint8(iter % 256))
		plan := mustPlan(t, 3, 20, 47)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var regCreated bool
		var regErr error
		go func() {
			defer wg.Done()
			<-start
			regCreated, regErr = c.RegisterPlan(plan)
		}()
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 48; i++ {
				c.Handle(Frame{Channel: c.id, Seq: uint32(i), Payload: payload(i)})
			}
		}()
		close(start)
		wg.Wait()

		switch regErr {
		case nil:
			if !regCreated {
				t.Fatalf("iter %d: sole registration reported as a retry", iter)
			}
			st := c.Status()
			if st.Status != "ok" {
				t.Fatalf("iter %d: registered plan on a correct stream but status=%q reason=%q",
					iter, st.Status, st.FailReason)
			}
			if st.NextSequence != 48 {
				t.Fatalf("iter %d: next=%d", iter, st.NextSequence)
			}
			for i, cp := range st.CheckpointPlan.Checkpoints {
				if cp.State != cpMatched {
					t.Fatalf("iter %d: checkpoint %d state=%s, want matched", iter, i, cp.State)
				}
			}
		case ErrBoundaryCrossed:
			if c.HasPlan() {
				t.Fatalf("iter %d: rejected plan was stored", iter)
			}
		default:
			t.Fatalf("iter %d: unexpected register error: %v", iter, regErr)
		}
	}
}

