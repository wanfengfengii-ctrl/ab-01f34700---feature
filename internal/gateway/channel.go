package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"slices"
	"sync"
)

// MaxAhead is how far ahead of nextSequence a frame may be and still be
// buffered: sequence numbers in [nextSequence, nextSequence+MaxAhead] are
// accepted, anything further is a window overflow and fails the channel.
const MaxAhead = 31

// Channel reassembles the in-order payload stream of one telemetry channel.
// Frames may arrive from many TCP connections concurrently, in any order,
// and may be retransmitted. The zero nextSequence is 0.
//
//   - identical retransmission (same sequence, same payload) is ignored;
//   - same sequence with different payload fails the channel permanently;
//   - a sequence more than MaxAhead ahead of nextSequence fails the channel
//     permanently;
//   - once failed, all further frames are ignored and the failure reason
//     stays stable.
type Channel struct {
	mu              sync.Mutex
	id              uint8
	next            uint32
	pending         map[uint32][]byte   // buffered out-of-order payloads, seq > next
	seen            map[uint32][32]byte // sha-256 of every accepted payload, by sequence
	hasher          hash.Hash           // running sha-256 over the contiguous payload
	contiguousBytes uint64
	failed          bool
	failReason      string
}

// NewChannel returns an empty channel assembler for id.
func NewChannel(id uint8) *Channel {
	return &Channel{
		id:      id,
		pending: make(map[uint32][]byte),
		seen:    make(map[uint32][32]byte),
		hasher:  sha256.New(),
	}
}

// Handle feeds one decoded frame into the channel. It is safe for
// concurrent use from multiple connection goroutines.
func (c *Channel) Handle(f Frame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return
	}
	sum := sha256.Sum256(f.Payload)
	if prev, ok := c.seen[f.Seq]; ok {
		if prev == sum {
			return // identical retransmission: ignore
		}
		c.fail(fmt.Sprintf("conflicting payload for sequence %d", f.Seq))
		return
	}
	// f.Seq < c.next is impossible here: every consumed sequence is in seen.
	if f.Seq-c.next > MaxAhead {
		c.fail(fmt.Sprintf("sequence %d exceeds reassembly window: next=%d, max=%d",
			f.Seq, c.next, c.next+MaxAhead))
		return
	}
	c.seen[f.Seq] = sum
	c.pending[f.Seq] = append([]byte(nil), f.Payload...)
	// Drain everything now contiguous into the digest.
	for {
		p, ok := c.pending[c.next]
		if !ok {
			return
		}
		c.hasher.Write(p)
		c.contiguousBytes += uint64(len(p))
		delete(c.pending, c.next)
		c.next++
	}
}

func (c *Channel) fail(reason string) {
	c.failed = true
	c.failReason = reason
	log.Printf("channel %d permanently failed: %s", c.id, reason)
}

// ChannelStatus is the API view of a channel.
type ChannelStatus struct {
	Channel         uint8    `json:"channel"`
	Status          string   `json:"status"` // "ok" or "failed"
	NextSequence    uint32   `json:"nextSequence"`
	SeenSequences   []uint32 `json:"seenSequences"`
	ContiguousBytes uint64   `json:"contiguousBytes"`
	SHA256          string   `json:"sha256"`
	FailReason      string   `json:"failReason,omitempty"`
}

// Status snapshots the channel state.
func (c *Channel) Status() ChannelStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make([]uint32, 0, len(c.seen))
	for s := range c.seen {
		seen = append(seen, s)
	}
	slices.Sort(seen)
	st := ChannelStatus{
		Channel:         c.id,
		Status:          "ok",
		NextSequence:    c.next,
		SeenSequences:   seen,
		ContiguousBytes: c.contiguousBytes,
		SHA256:          hex.EncodeToString(c.hasher.Sum(nil)),
	}
	if c.failed {
		st.Status = "failed"
		st.FailReason = c.failReason
	}
	return st
}
