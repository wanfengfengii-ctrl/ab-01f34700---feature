package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func payload(i int) []byte { return []byte(fmt.Sprintf("payload-%03d", i)) }

func feedSeqs(c *Channel, seqs ...int) {
	for _, s := range seqs {
		c.Handle(Frame{Channel: c.id, Seq: uint32(s), Payload: payload(s)})
	}
}

func digestOf(seqs ...int) string {
	h := sha256.New()
	for _, s := range seqs {
		h.Write(payload(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func seqs(lo, hi int) []int {
	var out []int
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}

func TestChannelInOrder(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, seqs(0, 9)...)
	st := c.Status()
	if st.Status != "ok" || st.NextSequence != 10 {
		t.Fatalf("status=%q next=%d", st.Status, st.NextSequence)
	}
	if st.ContiguousBytes != 10*uint64(len(payload(0))) {
		t.Fatalf("contiguousBytes=%d", st.ContiguousBytes)
	}
	if st.SHA256 != digestOf(seqs(0, 9)...) {
		t.Fatalf("sha256 mismatch")
	}
	if len(st.SeenSequences) != 10 {
		t.Fatalf("seen=%v", st.SeenSequences)
	}
}

func TestChannelOutOfOrderSameDigest(t *testing.T) {
	c := NewChannel(1)
	// Deliver 0..31 fully reversed; every frame is within the window of 32.
	for i := 31; i >= 0; i-- {
		feedSeqs(c, i)
	}
	st := c.Status()
	if st.NextSequence != 32 {
		t.Fatalf("next=%d, want 32", st.NextSequence)
	}
	if st.SHA256 != digestOf(seqs(0, 31)...) {
		t.Fatalf("digest differs from in-order delivery")
	}
}

func TestChannelBufferedUntilGapFilled(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0, 2, 4)
	if st := c.Status(); st.NextSequence != 1 {
		t.Fatalf("next=%d, want 1 (gap at 1)", st.NextSequence)
	}
	feedSeqs(c, 1, 3)
	st := c.Status()
	if st.NextSequence != 5 {
		t.Fatalf("next=%d, want 5", st.NextSequence)
	}
	if st.SHA256 != digestOf(0, 1, 2, 3, 4) {
		t.Fatalf("digest mismatch")
	}
}

func TestChannelIdenticalRetransmissionIgnored(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0, 1, 2)
	feedSeqs(c, 1)       // retransmission of a consumed frame
	feedSeqs(c, 5)       // buffered ahead
	feedSeqs(c, 5)       // retransmission of a pending frame
	feedSeqs(c, 3, 4, 5) // fill the gap; third copy of 5
	st := c.Status()
	if st.Status != "ok" {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
	if st.NextSequence != 6 || st.SHA256 != digestOf(0, 1, 2, 3, 4, 5) {
		t.Fatalf("next=%d sha=%s", st.NextSequence, st.SHA256)
	}
	if len(st.SeenSequences) != 6 {
		t.Fatalf("seen=%v", st.SeenSequences)
	}
}

func TestChannelConflictOnPendingFails(t *testing.T) {
	c := NewChannel(1)
	c.Handle(Frame{Channel: 1, Seq: 3, Payload: []byte("aaa")})
	c.Handle(Frame{Channel: 1, Seq: 3, Payload: []byte("bbb")})
	st := c.Status()
	if st.Status != "failed" || !strings.Contains(st.FailReason, "conflict") {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
}

func TestChannelConflictOnConsumedFails(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0, 1, 2)
	c.Handle(Frame{Channel: 1, Seq: 1, Payload: []byte("different")})
	st := c.Status()
	if st.Status != "failed" || !strings.Contains(st.FailReason, "conflict") {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
}

func TestChannelWindowBoundary(t *testing.T) {
	c := NewChannel(1)
	c.Handle(Frame{Channel: 1, Seq: 31, Payload: payload(31)}) // exactly 31 ahead: legal
	if st := c.Status(); st.Status != "ok" {
		t.Fatalf("seq 31 ahead of 0 must be accepted: %q", st.FailReason)
	}
	c2 := NewChannel(2)
	c2.Handle(Frame{Channel: 2, Seq: 32, Payload: payload(32)}) // 32 ahead: overflow
	st := c2.Status()
	if st.Status != "failed" || !strings.Contains(st.FailReason, "window") {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
}

func TestChannelWindowSlides(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, seqs(0, 31)...)                                // next is now 32
	c.Handle(Frame{Channel: 1, Seq: 63, Payload: payload(63)}) // 63-32=31: legal
	if st := c.Status(); st.Status != "ok" {
		t.Fatalf("seq 63 with next=32 must be accepted: %q", st.FailReason)
	}
	c.Handle(Frame{Channel: 1, Seq: 64, Payload: payload(64)}) // 64-32=32: overflow
	if st := c.Status(); st.Status != "failed" {
		t.Fatalf("seq 64 with next=32 must fail the channel")
	}
}

func TestChannelFailedIsPermanent(t *testing.T) {
	c := NewChannel(1)
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("a")})
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("b")}) // conflict -> failed
	before := c.Status()
	// Neither retransmissions nor new frames may change the state.
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("a")})
	c.Handle(Frame{Channel: 1, Seq: 1, Payload: []byte("x")})
	c.Handle(Frame{Channel: 1, Seq: 2, Payload: []byte("y")})
	after := c.Status()
	if after.Status != "failed" || after.FailReason != before.FailReason {
		t.Fatalf("failure not stable: %+v", after)
	}
	if after.NextSequence != before.NextSequence || after.SHA256 != before.SHA256 ||
		after.ContiguousBytes != before.ContiguousBytes {
		t.Fatalf("state moved after failure: before=%+v after=%+v", before, after)
	}
}

// cp builds a checkpoint at the end frame seq from the test payloads.
func cp(seq int) Checkpoint {
	var n int64
	for s := 0; s <= seq; s++ {
		n += int64(len(payload(s)))
	}
	return Checkpoint{Sequence: uint32(seq), ContiguousBytes: n, SHA256: digestOf(seqs(0, seq)...)}
}

func TestCheckpointVerifiesAtBoundary(t *testing.T) {
	c := NewChannel(1)
	plan := []Checkpoint{cp(2), cp(4)}
	res, err := c.RegisterPlan(plan)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.Replayed || len(res.Statuses) != 2 ||
		res.Statuses[0].State != CheckpointPending || res.Statuses[1].State != CheckpointPending {
		t.Fatalf("initial statuses: %+v", res.Statuses)
	}
	feedSeqs(c, 0, 1) // next=2: boundary frame 2 not consumed yet
	if states := c.CheckpointStatuses(); states[0].State != CheckpointPending {
		t.Fatalf("checkpoint 2 checked before its frame: %v", states[0].State)
	}
	feedSeqs(c, 2, 3, 4) // drains through both boundaries
	st := c.Status()
	if st.Status != "ok" {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
	if st.Checkpoints[0].State != CheckpointVerified || st.Checkpoints[1].State != CheckpointVerified {
		t.Fatalf("checkpoints: %+v", st.Checkpoints)
	}
}

func TestCheckpointBufferedHigherFramesExcluded(t *testing.T) {
	c := NewChannel(1)
	// Frame 4 is buffered long before the gap is filled.
	feedSeqs(c, 4)
	plan := []Checkpoint{cp(1), cp(4)}
	if _, err := c.RegisterPlan(plan); err != nil {
		t.Fatalf("register: %v", err)
	}
	feedSeqs(c, 0, 1) // crosses checkpoint 1; buffered frame 4 must not enter the digest
	st := c.Status()
	if st.Checkpoints[0].State != CheckpointVerified {
		t.Fatalf("checkpoint 1: %+v", st.Checkpoints[0])
	}
	if st.Checkpoints[1].State != CheckpointPending {
		t.Fatalf("checkpoint 4 must stay pending: %+v", st.Checkpoints[1])
	}
	if st.NextSequence != 2 {
		t.Fatalf("next=%d, want 2", st.NextSequence)
	}
	feedSeqs(c, 2, 3, 4)
	st = c.Status()
	if st.Status != "ok" || st.Checkpoints[1].State != CheckpointVerified {
		t.Fatalf("status=%q cps=%+v", st.Status, st.Checkpoints)
	}
}

func TestCheckpointMismatchFailsPermanently(t *testing.T) {
	c := NewChannel(1)
	bad := cp(2)
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := c.RegisterPlan([]Checkpoint{cp(0), bad, cp(4)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	feedSeqs(c, 0)    // checkpoint 0 verifies
	feedSeqs(c, 1, 2) // checkpoint 2 mismatches
	st := c.Status()
	if st.Status != "failed" {
		t.Fatalf("status=%q, want failed", st.Status)
	}
	failed := st.Checkpoints[1]
	if failed.State != CheckpointFailed ||
		failed.ActualSHA256 != cp(2).SHA256 || failed.ActualContiguousBytes != cp(2).ContiguousBytes {
		t.Fatalf("failed checkpoint detail: %+v", failed)
	}
	if st.Checkpoints[0].State != CheckpointVerified || st.Checkpoints[2].State != CheckpointPending {
		t.Fatalf("other checkpoints: %+v", st.Checkpoints)
	}
	if !strings.Contains(st.FailReason, "checkpoint") {
		t.Fatalf("failReason=%q", st.FailReason)
	}
	// Later frames never change the frozen state.
	before := c.Status()
	feedSeqs(c, 3, 4, 5)
	after := c.Status()
	if after.Status != "failed" || after.FailReason != before.FailReason ||
		after.NextSequence != before.NextSequence || after.SHA256 != before.SHA256 {
		t.Fatalf("state moved after checkpoint failure: before=%+v after=%+v", before, after)
	}
}

func TestCheckpointRegisterCrossedBoundary(t *testing.T) {
	c := NewChannel(1)
	feedSeqs(c, 0, 1) // next=2: frame 1 consumed
	if _, err := c.RegisterPlan([]Checkpoint{cp(1)}); !errors.Is(err, ErrCheckpointPlanLate) {
		t.Fatalf("register after crossing boundary: err=%v, want ErrCheckpointPlanLate", err)
	}
	if c.HasPlan() {
		t.Fatalf("rejected plan must not be stored")
	}
	// next == sequence (frame not yet consumed) is still allowed.
	c3 := NewChannel(3)
	c3.Handle(Frame{Channel: 3, Seq: 0, Payload: payload(0)}) // next=1
	plan := []Checkpoint{cp(1)}
	if _, err := c3.RegisterPlan(plan); err != nil {
		t.Fatalf("register with next==sequence must succeed: %v", err)
	}
	// next > sequence stays rejected even with no plan stored in between.
	c4 := NewChannel(4)
	c4.Handle(Frame{Channel: 4, Seq: 1, Payload: payload(1)}) // buffered, next=0
	c4.Handle(Frame{Channel: 4, Seq: 0, Payload: payload(0)}) // drains, next=2
	if _, err := c4.RegisterPlan([]Checkpoint{cp(1)}); !errors.Is(err, ErrCheckpointPlanLate) {
		t.Fatalf("register after drain crossed boundary: err=%v, want ErrCheckpointPlanLate", err)
	}
}

func TestCheckpointIdempotentReplayAndConflict(t *testing.T) {
	c := NewChannel(1)
	plan := []Checkpoint{cp(1), cp(3)}
	if _, err := c.RegisterPlan(plan); err != nil {
		t.Fatalf("register: %v", err)
	}
	feedSeqs(c, 0, 1)
	res, err := c.RegisterPlan(plan) // identical retry
	if err != nil || !res.Replayed {
		t.Fatalf("identical retry: err=%v replayed=%v", err, res.Replayed)
	}
	if res.Statuses[0].State != CheckpointVerified || res.Statuses[1].State != CheckpointPending {
		t.Fatalf("replayed states: %+v", res.Statuses)
	}
	different := []Checkpoint{cp(1), cp(4)}
	if _, err := c.RegisterPlan(different); !errors.Is(err, ErrCheckpointPlanExists) {
		t.Fatalf("different plan: err=%v, want ErrCheckpointPlanExists", err)
	}
	// The original plan is untouched.
	if states := c.CheckpointStatuses(); states[1].Sequence != 3 {
		t.Fatalf("plan overwritten by conflicting request: %+v", states)
	}
}

func TestCheckpointRegisterOnFailedChannel(t *testing.T) {
	c := NewChannel(1)
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("a")})
	c.Handle(Frame{Channel: 1, Seq: 0, Payload: []byte("b")}) // conflict
	if _, err := c.RegisterPlan([]Checkpoint{cp(0)}); !errors.Is(err, ErrChannelFailed) {
		t.Fatalf("register on failed channel: err=%v, want ErrChannelFailed", err)
	}
}

func TestCheckpointReorderedAcrossCheckpoints(t *testing.T) {
	// Fully reversed delivery of 0..15 with four checkpoints must verify all.
	c := NewChannel(1)
	plan := []Checkpoint{cp(3), cp(7), cp(11), cp(15)}
	if _, err := c.RegisterPlan(plan); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := 15; i >= 0; i-- {
		feedSeqs(c, i)
	}
	st := c.Status()
	if st.Status != "ok" {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
	for i, cs := range st.Checkpoints {
		if cs.State != CheckpointVerified {
			t.Fatalf("checkpoint %d (seq %d): %+v", i, cs.Sequence, cs)
		}
	}
}

func TestCheckpointRegistrationRace(t *testing.T) {
	// Registration and inflow race at the first boundary (seq 0). Every
	// adjudication must be atomic: either the plan lands before frame 0 is
	// consumed and verifies, or it is rejected — never a false mismatch.
	for iter := 0; iter < 200; iter++ {
		c := NewChannel(1)
		done := make(chan struct{})
		go func() {
			c.Handle(Frame{Channel: 1, Seq: 0, Payload: payload(0)})
			close(done)
		}()
		res, err := c.RegisterPlan([]Checkpoint{cp(0)})
		<-done
		if err != nil {
			if !errors.Is(err, ErrCheckpointPlanLate) {
				t.Fatalf("iter %d: unexpected err %v", iter, err)
			}
			continue
		}
		// Plan was accepted: frame 0 may have consumed after registration.
		st := c.Status()
		if st.Status != "ok" {
			t.Fatalf("iter %d: false failure: %+v", iter, st)
		}
		if st.Checkpoints[0].State != CheckpointPending && st.Checkpoints[0].State != CheckpointVerified {
			t.Fatalf("iter %d: state=%s", iter, st.Checkpoints[0].State)
		}
		_ = res
	}
}
