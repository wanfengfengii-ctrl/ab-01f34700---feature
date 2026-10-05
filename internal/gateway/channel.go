package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// Checkpoint states reported by the checkpoint-plan API.
const (
	// CheckpointPending means the boundary frame has not been consumed yet.
	CheckpointPending = "pending"
	// CheckpointVerified means the cumulative result matched at the boundary.
	CheckpointVerified = "verified"
	// CheckpointFailed means the cumulative result mismatched at the boundary.
	CheckpointFailed = "failed"
)

// Registration errors returned by Channel.RegisterPlan. The HTTP layer maps
// all of them to 409 Conflict.
var (
	ErrCheckpointPlanExists = errors.New("channel already has a different checkpoint plan")
	ErrCheckpointPlanLate   = errors.New("inflow already crossed the first checkpoint boundary")
	ErrChannelFailed        = errors.New("channel is permanently failed")
)

// Checkpoint is one trusted cumulative checkpoint: once reassembly has
// consumed every frame with sequence up to and including Sequence, the
// running contiguous byte count and SHA-256 must equal ContiguousBytes and
// SHA256. SHA256 is lowercase hex.
type Checkpoint struct {
	Sequence        uint32 `json:"sequence"`
	ContiguousBytes int64  `json:"contiguousBytes"`
	SHA256          string `json:"sha256"`
}

// CheckpointStatus is the current state of one registered checkpoint.
type CheckpointStatus struct {
	Sequence              uint32 `json:"sequence"`
	ContiguousBytes       int64  `json:"contiguousBytes"`
	SHA256                string `json:"sha256"`
	State                 string `json:"state"` // CheckpointPending/Verified/Failed
	ActualContiguousBytes int64  `json:"actualContiguousBytes,omitempty"`
	ActualSHA256          string `json:"actualSha256,omitempty"`
}

// checkpointFailure records the stable actual cumulative result at the
// checkpoint whose mismatch permanently failed the channel. The expected
// values stay in the plan entry and are returned alongside in Status.
type checkpointFailure struct {
	sequence     uint32
	actualBytes  int64
	actualSHA256 string
}

// RegisterPlanResult is returned by Channel.RegisterPlan.
type RegisterPlanResult struct {
	// Replayed is true when an identical plan was already registered and
	// Statuses are the current states rather than a fresh registration.
	Replayed bool
	Statuses []CheckpointStatus
}

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
	// plan is the registered checkpoint plan (nil until one is registered);
	// cpState[i] tracks plan[i] (pending/verified/failed); checkpointFail
	// records the mismatch when a checkpoint fails the channel.
	plan           []Checkpoint
	cpState        []string
	checkpointFail *checkpointFailure
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
		// A frame boundary: verify every checkpoint whose end frame was the
		// sequence just consumed. Only the cumulative result up to this
		// sequence is inspected; buffered higher sequences never enter it.
		c.verifyCheckpointsLocked()
		if c.failed {
			return
		}
	}
}

// verifyCheckpointsLocked checks every pending checkpoint whose boundary
// sequence has just been consumed (next is now Sequence+1). A mismatch fails
// the channel permanently and records the expected/actual result. Caller
// must hold c.mu.
func (c *Channel) verifyCheckpointsLocked() {
	if c.plan == nil {
		return
	}
	for i := range c.plan {
		if c.cpState[i] != CheckpointPending {
			continue
		}
		if c.next != c.plan[i].Sequence+1 {
			continue
		}
		actualSum := hex.EncodeToString(c.hasher.Sum(nil))
		actualBytes := int64(c.contiguousBytes)
		if actualBytes == c.plan[i].ContiguousBytes && actualSum == c.plan[i].SHA256 {
			c.cpState[i] = CheckpointVerified
			log.Printf("channel %d checkpoint at sequence %d verified", c.id, c.plan[i].Sequence)
			continue
		}
		c.cpState[i] = CheckpointFailed
		c.checkpointFail = &checkpointFailure{
			sequence:     c.plan[i].Sequence,
			actualBytes:  actualBytes,
			actualSHA256: actualSum,
		}
		c.fail(fmt.Sprintf("checkpoint mismatch at sequence %d: expected %d bytes sha256=%s, got %d bytes sha256=%s",
			c.plan[i].Sequence, c.plan[i].ContiguousBytes, c.plan[i].SHA256,
			actualBytes, actualSum))
		return
	}
}

// RegisterPlan atomically registers plan for the channel. Registration races
// with TCP inflow under the same lock: if reassembly has already consumed the
// first checkpoint's boundary frame, the whole plan is rejected.
//
//   - a channel that is permanently failed is rejected;
//   - the first plan wins; registering an identical plan is idempotent and
//     returns the current per-checkpoint states (Replayed=true);
//   - registering a different plan returns ErrCheckpointPlanExists.
func (c *Channel) RegisterPlan(plan []Checkpoint) (RegisterPlanResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The single accepted plan is authoritative for the channel's lifetime:
	// an identical retry always replays current states (even after a
	// checkpoint failed the channel); a different one is always a conflict.
	if c.plan != nil {
		if !plansEqual(c.plan, plan) {
			return RegisterPlanResult{}, ErrCheckpointPlanExists
		}
		return RegisterPlanResult{Replayed: true, Statuses: c.checkpointStatusesLocked()}, nil
	}
	if c.failed {
		return RegisterPlanResult{}, ErrChannelFailed
	}
	// Atomic adjudication against concurrent inflow: the boundary is crossed
	// once the end frame is consumed, i.e. next > Sequence. Equal is allowed
	// (the boundary frame is not consumed yet).
	if c.next > plan[0].Sequence {
		return RegisterPlanResult{}, ErrCheckpointPlanLate
	}
	c.plan = plan
	c.cpState = make([]string, len(plan))
	for i := range c.cpState {
		c.cpState[i] = CheckpointPending
	}
	log.Printf("channel %d registered %d checkpoint(s)", c.id, len(plan))
	return RegisterPlanResult{Statuses: c.checkpointStatusesLocked()}, nil
}

// checkpointStatusesLocked snapshots every checkpoint's state. Caller holds
// c.mu.
func (c *Channel) checkpointStatusesLocked() []CheckpointStatus {
	if c.plan == nil {
		return nil
	}
	out := make([]CheckpointStatus, len(c.plan))
	for i := range c.plan {
		cs := CheckpointStatus{
			Sequence:        c.plan[i].Sequence,
			ContiguousBytes: c.plan[i].ContiguousBytes,
			SHA256:          c.plan[i].SHA256,
			State:           c.cpState[i],
		}
		if c.checkpointFail != nil && c.checkpointFail.sequence == c.plan[i].Sequence {
			cs.ActualContiguousBytes = c.checkpointFail.actualBytes
			cs.ActualSHA256 = c.checkpointFail.actualSHA256
		}
		out[i] = cs
	}
	return out
}

// CheckpointStatuses snapshots the registered plan and per-checkpoint state.
// It returns nil when no plan is registered.
func (c *Channel) CheckpointStatuses() []CheckpointStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkpointStatusesLocked()
}

// HasPlan reports whether a plan is registered.
func (c *Channel) HasPlan() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.plan != nil
}

// plansEqual compares two checkpoint plans field by field and in order.
func plansEqual(a, b []Checkpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	// Checkpoints is present only when a checkpoint plan is registered.
	Checkpoints []CheckpointStatus `json:"checkpoints,omitempty"`
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
	if c.plan != nil {
		st.Checkpoints = c.checkpointStatusesLocked()
	}
	if c.failed {
		st.Status = "failed"
		st.FailReason = c.failReason
	}
	return st
}
