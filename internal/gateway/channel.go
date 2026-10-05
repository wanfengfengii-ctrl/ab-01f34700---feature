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

// Checkpoint is one trusted boundary of a checkpoint plan. When contiguous
// reassembly reaches Sequence (i.e. frames 0..Sequence have been consumed),
// the cumulative stream must be exactly ContiguousBytes long and hash to the
// lowercase hex SHA-256 in SHA256.
type Checkpoint struct {
	Sequence        uint32 `json:"sequence"`
	ContiguousBytes uint64 `json:"contiguousBytes"`
	SHA256          string `json:"sha256"`
}

// CheckpointState values.
const (
	cpPending   = "pending"   // boundary not reached yet
	cpMatched   = "matched"   // cumulative result matched at the boundary
	cpMismatch  = "mismatched" // cumulative result differed; channel is failed
)

// CheckpointResult is the API view of one planned checkpoint: the registered
// expectation plus its current state and, on mismatch, the actual result.
type CheckpointResult struct {
	Sequence              uint32 `json:"sequence"`
	ContiguousBytes       uint64 `json:"contiguousBytes"`
	SHA256                string `json:"sha256"`
	State                 string `json:"state"`
	ActualContiguousBytes uint64 `json:"actualContiguousBytes,omitempty"`
	ActualSHA256          string `json:"actualSha256,omitempty"`
}

// CheckpointPlanStatus is the API view of a channel's single plan.
type CheckpointPlanStatus struct {
	Checkpoints []CheckpointResult `json:"checkpoints"`
}

// Registration outcomes, mapped to HTTP status by the server.
var (
	// ErrPlanConflict: a plan with different content is already registered.
	ErrPlanConflict = errors.New("a different checkpoint plan is already registered for this channel")
	// ErrBoundaryCrossed: ingest already moved past the plan's first boundary.
	ErrBoundaryCrossed = errors.New("ingest already passed the first checkpoint boundary")
	// ErrChannelFailed: the channel is permanently failed and accepts no plan.
	ErrChannelFailed = errors.New("channel is permanently failed")
)

// ValidateCheckpoints returns "" when cps is a well-formed plan request
// (1–4 entries, strictly increasing sequences and byte counts, 64 lowercase
// hex SHA-256 values), otherwise a human-readable reason.
func ValidateCheckpoints(cps []Checkpoint) string {
	if len(cps) < 1 || len(cps) > 4 {
		return "checkpoints: need between 1 and 4 entries"
	}
	prevSeq := uint32(0)
	prevBytes := uint64(0)
	for i, cp := range cps {
		if i > 0 && cp.Sequence <= prevSeq {
			return fmt.Sprintf("checkpoints[%d]: sequences must be strictly increasing", i)
		}
		if cp.ContiguousBytes == 0 {
			return fmt.Sprintf("checkpoints[%d]: contiguousBytes must be greater than 0", i)
		}
		if i > 0 && cp.ContiguousBytes <= prevBytes {
			return fmt.Sprintf("checkpoints[%d]: contiguousBytes must be strictly increasing", i)
		}
		if !isLowerSHA256(cp.SHA256) {
			return fmt.Sprintf("checkpoints[%d]: sha256 must be 64 lowercase hex characters", i)
		}
		prevSeq = cp.Sequence
		prevBytes = cp.ContiguousBytes
	}
	return ""
}

func isLowerSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// checkpointState extends the registered expectation with live verdict data.
type checkpointState struct {
	Checkpoint
	state       string
	actualBytes uint64
	actualSHA   string
}

func (cp *checkpointState) result() CheckpointResult {
	r := CheckpointResult{
		Sequence:        cp.Sequence,
		ContiguousBytes: cp.ContiguousBytes,
		SHA256:          cp.SHA256,
		State:           cp.state,
	}
	if cp.state == cpMismatch {
		r.ActualContiguousBytes = cp.actualBytes
		r.ActualSHA256 = cp.actualSHA
	}
	return r
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
//
// A channel may hold at most one checkpoint plan. The plan is checked as the
// contiguous stream crosses each boundary: only the cumulative result up to
// that boundary's sequence is examined, even if higher sequences are already
// buffered. Any mismatch fails the channel permanently.
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
	plan            []*checkpointState // all registered boundaries, nil if none
	planIdx         int                // first boundary not yet matched
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
	// Drain everything now contiguous into the digest. Checkpoint boundaries
	// are evaluated the moment the stream reaches them, against the cumulative
	// result up to that sequence only: higher buffered frames are drained in
	// later loop iterations and cannot enter the checked digest.
	for {
		p, ok := c.pending[c.next]
		if !ok {
			return
		}
		c.hasher.Write(p)
		c.contiguousBytes += uint64(len(p))
		delete(c.pending, c.next)
		c.next++
		if c.evaluateBoundary() {
			return
		}
	}
}

// evaluateBoundary must be called with c.mu held, immediately after the
// contiguous stream advanced (c.next incremented). If the advance reached the
// next pending checkpoint boundary it verifies the cumulative result and, on
// mismatch, fails the channel. It reports true when the channel is failed.
func (c *Channel) evaluateBoundary() bool {
	if c.planIdx >= len(c.plan) {
		return false
	}
	cp := c.plan[c.planIdx]
	if c.next != cp.Sequence+1 {
		return false
	}
	actualSHA := hex.EncodeToString(c.hasher.Sum(nil))
	if c.contiguousBytes == cp.ContiguousBytes && actualSHA == cp.SHA256 {
		cp.state = cpMatched
		c.planIdx++
		log.Printf("channel %d checkpoint at sequence %d matched (%d bytes)",
			c.id, cp.Sequence, cp.ContiguousBytes)
		return false
	}
	cp.state = cpMismatch
	cp.actualBytes = c.contiguousBytes
	cp.actualSHA = actualSHA
	c.fail(fmt.Sprintf("checkpoint mismatch at sequence %d: expected %d bytes sha256=%s, got %d bytes sha256=%s",
		cp.Sequence, cp.ContiguousBytes, cp.SHA256, c.contiguousBytes, actualSHA))
	return true
}

// RegisterPlan atomically registers cps as the channel's single checkpoint
// plan. The plan is rejected (and no state changes) when the channel is
// failed, when ingest already passed the first boundary (c.next > first
// sequence), or when a different plan is already registered. Retrying with
// the identical content succeeds and the caller may read the current state
// via PlanStatus. It reports created=true on the first registration and
// created=false for an identical retry. The decision is atomic with respect
// to concurrent frame handling.
func (c *Channel) RegisterPlan(cps []Checkpoint) (created bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return false, ErrChannelFailed
	}
	if c.plan != nil {
		if plansEqual(c.plan, cps) {
			return false, nil
		}
		return false, ErrPlanConflict
	}
	if c.next > cps[0].Sequence {
		return false, ErrBoundaryCrossed
	}
	c.plan = make([]*checkpointState, len(cps))
	for i, cp := range cps {
		c.plan[i] = &checkpointState{Checkpoint: cp, state: cpPending}
	}
	log.Printf("channel %d: checkpoint plan registered with %d boundary(s), first at sequence %d",
		c.id, len(cps), cps[0].Sequence)
	return true, nil
}

func plansEqual(have []*checkpointState, want []Checkpoint) bool {
	if len(have) != len(want) {
		return false
	}
	for i, cp := range have {
		if cp.Checkpoint != want[i] {
			return false
		}
	}
	return true
}

// PlanStatus snapshots the registered plan with per-checkpoint state. All
// boundaries — pending, matched and the mismatched one — are returned in
// registration order.
func (c *Channel) PlanStatus() CheckpointPlanStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CheckpointResult, 0, len(c.plan))
	for _, cp := range c.plan {
		out = append(out, cp.result())
	}
	return CheckpointPlanStatus{Checkpoints: out}
}

// HasPlan reports whether a plan is registered.
func (c *Channel) HasPlan() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.plan != nil
}

func (c *Channel) fail(reason string) {
	c.failed = true
	c.failReason = reason
	log.Printf("channel %d permanently failed: %s", c.id, reason)
}

// ChannelStatus is the API view of a channel.
type ChannelStatus struct {
	Channel         uint8                 `json:"channel"`
	Status          string                `json:"status"` // "ok" or "failed"
	NextSequence    uint32                `json:"nextSequence"`
	SeenSequences   []uint32              `json:"seenSequences"`
	ContiguousBytes uint64                `json:"contiguousBytes"`
	SHA256          string                `json:"sha256"`
	FailReason      string                `json:"failReason,omitempty"`
	CheckpointPlan  *CheckpointPlanStatus `json:"checkpointPlan,omitempty"`
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
		results := make([]CheckpointResult, 0, len(c.plan))
		for _, cp := range c.plan {
			results = append(results, cp.result())
		}
		st.CheckpointPlan = &CheckpointPlanStatus{Checkpoints: results}
	}
	if c.failed {
		st.Status = "failed"
		st.FailReason = c.failReason
	}
	return st
}
