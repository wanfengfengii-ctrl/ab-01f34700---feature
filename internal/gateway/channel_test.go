package gateway

import (
	"crypto/sha256"
	"encoding/hex"
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
