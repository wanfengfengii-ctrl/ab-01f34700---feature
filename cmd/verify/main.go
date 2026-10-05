// Command verify is the live smoke client: it writes adversarial telemetry
// streams to a running gateway over real TCP connections and asserts the
// HTTP API reports the expected digests and failure states.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var syncWord = []byte{0x1A, 0xCF, 0xFC, 0x1D}

const (
	totalFrames = 48
	waitTimeout = 15 * time.Second
)

type channelStatus struct {
	Channel         uint8      `json:"channel"`
	Status          string     `json:"status"`
	NextSequence    uint32     `json:"nextSequence"`
	SeenSequences   []uint32   `json:"seenSequences"`
	ContiguousBytes uint64     `json:"contiguousBytes"`
	SHA256          string     `json:"sha256"`
	FailReason      string     `json:"failReason"`
	Checkpoints     []cpStatus `json:"checkpoints"`
}

type cpStatus struct {
	Sequence              uint32 `json:"sequence"`
	ContiguousBytes       int64  `json:"contiguousBytes"`
	SHA256                string `json:"sha256"`
	State                 string `json:"state"`
	ActualContiguousBytes int64  `json:"actualContiguousBytes"`
	ActualSHA256          string `json:"actualSha256"`
}

type checkpoint struct {
	Sequence        uint32 `json:"sequence"`
	ContiguousBytes int64  `json:"contiguousBytes"`
	SHA256          string `json:"sha256"`
}

type planRequest struct {
	Checkpoints []checkpoint `json:"checkpoints"`
}

type planResponse struct {
	Replayed    bool       `json:"replayed"`
	Checkpoints []cpStatus `json:"checkpoints"`
	Error       string     `json:"error"`
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// frameBytes encodes one frame: sync, channel, big-endian seq, big-endian
// length, payload, big-endian CRC32-IEEE over channel..payload.
func frameBytes(channel uint8, seq uint32, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(syncWord)
	b.WriteByte(channel)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], seq)
	b.Write(tmp[:])
	binary.BigEndian.PutUint16(tmp[:], uint16(len(payload)))
	b.Write(tmp[:2])
	b.Write(payload)
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.ChecksumIEEE(b.Bytes()[4:]))
	b.Write(crc[:])
	return b.Bytes()
}

// payloadFor deterministically derives the payload for a sequence number so
// the expected digest can be recomputed independently of the gateway.
func payloadFor(i int) []byte {
	n := 1 + (i*37)%300
	p := make([]byte, n)
	for j := range p {
		p[j] = byte(i*7 + j*13)
	}
	return p
}

func concatFrames(ch uint8, seqs ...int) []byte {
	var b bytes.Buffer
	for _, s := range seqs {
		b.Write(frameBytes(ch, uint32(s), payloadFor(s)))
	}
	return b.Bytes()
}

func dial(addr string) (net.Conn, error) {
	var last error
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial %s: %w", addr, last)
}

// writeChunks writes data in pieces sized by size(off) to exercise
// arbitrary TCP fragmentation.
func writeChunks(c net.Conn, data []byte, size func(off int) int) error {
	for off := 0; off < len(data); {
		n := size(off)
		if n > len(data)-off {
			n = len(data) - off
		}
		if _, err := c.Write(data[off : off+n]); err != nil {
			return err
		}
		off += n
	}
	return nil
}

// senderByteByByte ships the given frames one byte per TCP write.
func senderByteByByte(addr string, ch uint8, seqs ...int) error {
	c, err := dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return writeChunks(c, concatFrames(ch, seqs...), func(int) int { return 1 })
}

// senderGarbage glues garbage, a CRC-corrupt frame and two illegal-length
// candidates in front of valid out-of-order frames 10..19, all in one write.
func senderGarbage(addr string, ch uint8) error {
	return senderGarbageRange(addr, ch, 10, 19)
}

// senderGarbageRange is senderGarbage generalized to any contiguous range;
// the valid frames are emitted in a fixed permuted order.
func senderGarbageRange(addr string, ch uint8, lo, hi int) error {
	c, err := dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	var b bytes.Buffer
	b.Write([]byte{0x00, 0xFF, 0x1A, 0x13, 0x37, 0x1A, 0xCF}) // garbage ending in a partial sync word
	bad := frameBytes(ch, 77, []byte("XXXX"))
	bad[len(bad)-1] ^= 0xFF // corrupt the CRC
	b.Write(bad)
	b.Write(syncWord)
	b.WriteByte(ch)
	b.Write([]byte{0, 0, 0, 88}) // seq 88
	b.Write([]byte{0, 0})        // length 0: illegal
	b.Write([]byte{0xAA, 0xBB, 0xCC})
	b.Write(syncWord)
	b.WriteByte(ch)
	b.Write([]byte{0, 0, 0, 89}) // seq 89
	b.Write([]byte{0x07, 0xD0})  // length 2000 > 1024: illegal
	b.Write([]byte{0x01, 0x02, 0x03})
	for s := hi; s >= lo; s-- {
		b.Write(frameBytes(ch, uint32(s), payloadFor(s)))
	}
	_, err = c.Write(b.Bytes())
	return err
}

// senderChunked ships frames 20..31 plus identical retransmissions of 5 and
// 25 (which must be ignored) in irregular chunk sizes.
func senderChunked(addr string, ch uint8) error {
	c, err := dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	var b bytes.Buffer
	b.Write(rangeFrames(ch, 20, 31))
	b.Write(frameBytes(ch, 5, payloadFor(5)))
	b.Write(frameBytes(ch, 25, payloadFor(25)))
	return writeChunks(c, b.Bytes(), func(off int) int { return 1 + (off*11)%64 })
}

// senderChunkedRange writes frames lo..hi in irregular chunk sizes.
func senderChunkedRange(addr string, ch uint8, lo, hi int) error {
	c, err := dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return writeChunks(c, rangeFrames(ch, lo, hi), func(off int) int { return 1 + (off*11)%64 })
}

func rangeFrames(ch uint8, lo, hi int) []byte {
	var b bytes.Buffer
	for s := lo; s <= hi; s++ {
		b.Write(frameBytes(ch, uint32(s), payloadFor(s)))
	}
	return b.Bytes()
}

func getStatus(base string, id int) (channelStatus, int, error) {
	var st channelStatus
	resp, err := http.Get(fmt.Sprintf("%s/api/channels/%d", base, id))
	if err != nil {
		return st, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return st, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return st, resp.StatusCode, nil
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return st, resp.StatusCode, fmt.Errorf("decode status: %w", err)
	}
	return st, resp.StatusCode, nil
}

func waitFor(desc string, cond func() (bool, error)) error {
	deadline := time.Now().Add(waitTimeout)
	var err error
	for {
		var ok bool
		ok, err = cond()
		if err == nil && ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s (last err: %v)", desc, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForSequence(base string, ch int, next uint32) error {
	return waitFor(fmt.Sprintf("channel %d nextSequence==%d", ch, next), func() (bool, error) {
		st, _, err := getStatus(base, int(ch))
		return st.NextSequence == next, err
	})
}

func waitForFailed(base string, ch int) error {
	return waitFor(fmt.Sprintf("channel %d failed", ch), func() (bool, error) {
		st, _, err := getStatus(base, int(ch))
		return st.Status == "failed", err
	})
}

func waitForChannelExists(base string, ch int) error {
	return waitFor(fmt.Sprintf("channel %d exists", ch), func() (bool, error) {
		_, code, err := getStatus(base, ch)
		return code == http.StatusOK, err
	})
}

// cumulativeDigest independently computes the contiguous byte count and
// SHA-256 over payloads 0..upTo in sequence order.
func cumulativeDigest(upTo int) (int64, string) {
	h := sha256.New()
	var n int64
	for i := 0; i <= upTo; i++ {
		p := payloadFor(i)
		h.Write(p)
		n += int64(len(p))
	}
	return n, hex.EncodeToString(h.Sum(nil))
}

func planCheckpoints(ups ...int) []checkpoint {
	cps := make([]checkpoint, len(ups))
	for i, up := range ups {
		n, sum := cumulativeDigest(up)
		cps[i] = checkpoint{Sequence: uint32(up), ContiguousBytes: n, SHA256: sum}
	}
	return cps
}

func postPlan(base string, ch int, cps []checkpoint) (planResponse, int, error) {
	var res planResponse
	b, err := json.Marshal(planRequest{Checkpoints: cps})
	if err != nil {
		return res, 0, err
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/channels/%d/checkpoint-plan", base, ch),
		"application/json", bytes.NewReader(b))
	if err != nil {
		return res, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return res, resp.StatusCode, err
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &res); err != nil {
			return res, resp.StatusCode, fmt.Errorf("decode plan response: %w", err)
		}
	} else {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		res.Error = e.Error
	}
	return res, resp.StatusCode, nil
}

// pickChannels finds seven currently-unknown channels: five to exercise
// (happy path, conflict, window overflow, checkpoints, checkpoint mismatch,
// late checkpoint) and one that must stay unknown for the 404 check. This
// keeps verify re-runnable against a long-lived gateway that still holds
// state from previous runs.
func pickChannels(base string) (happy, conflict, window, cpOK, cpBad, cpLate, unknown uint8, err error) {
	off := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(256)
	var free []uint8
	for i := 0; i < 256 && len(free) < 7; i++ {
		id := uint8((off + i) % 256)
		_, code, e := getStatus(base, int(id))
		if e != nil {
			return 0, 0, 0, 0, 0, 0, 0, fmt.Errorf("probe channel %d: %w", id, e)
		}
		if code == http.StatusNotFound {
			free = append(free, id)
		}
	}
	if len(free) < 7 {
		return 0, 0, 0, 0, 0, 0, 0, fmt.Errorf("need 7 unused channels, found %d", len(free))
	}
	return free[0], free[1], free[2], free[3], free[4], free[5], free[6], nil
}

// happyPath delivers frames 0..47 of channel ch across concurrent
// connections — out of order, glued to bad frames, and byte-by-byte — and
// requires the gateway digest to equal the locally computed one.
func happyPath(tcpAddr, httpBase string, ch uint8) error {
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	run := func(f func() error) {
		defer wg.Done()
		if err := f(); err != nil {
			errs <- err
		}
	}
	wg.Add(3)
	go run(func() error { return senderByteByByte(tcpAddr, ch, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9) })
	go run(func() error { return senderGarbage(tcpAddr, ch) })
	go run(func() error { return senderChunked(tcpAddr, ch) })
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	}
	if err := waitForSequence(httpBase, int(ch), 32); err != nil {
		return err
	}
	// Phase 2: window has slid; sequences 32..47 arrive reversed, byte-by-byte.
	if err := senderByteByByte(tcpAddr, ch,
		47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32); err != nil {
		return err
	}
	if err := waitForSequence(httpBase, int(ch), totalFrames); err != nil {
		return err
	}

	st, code, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("GET channel %d: http %d", ch, code)
	}
	h := sha256.New()
	var totalBytes uint64
	for i := 0; i < totalFrames; i++ {
		p := payloadFor(i)
		h.Write(p)
		totalBytes += uint64(len(p))
	}
	if st.Status != "ok" {
		return fmt.Errorf("status=%q failReason=%q, want ok", st.Status, st.FailReason)
	}
	if st.NextSequence != totalFrames {
		return fmt.Errorf("nextSequence=%d, want %d", st.NextSequence, totalFrames)
	}
	if st.ContiguousBytes != totalBytes {
		return fmt.Errorf("contiguousBytes=%d, want %d", st.ContiguousBytes, totalBytes)
	}
	if want := hex.EncodeToString(h.Sum(nil)); st.SHA256 != want {
		return fmt.Errorf("sha256=%s, want %s", st.SHA256, want)
	}
	if len(st.SeenSequences) != totalFrames {
		return fmt.Errorf("seenSequences has %d entries, want %d", len(st.SeenSequences), totalFrames)
	}
	for i, s := range st.SeenSequences {
		if s != uint32(i) {
			return fmt.Errorf("seenSequences[%d]=%d, want %d", i, s, i)
		}
	}
	return nil
}

// conflictPath sends two different payloads for sequence 0 and requires a
// permanent, stable failure with a clear reason.
func conflictPath(tcpAddr, httpBase string, ch uint8) error {
	c, err := dial(tcpAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(frameBytes(ch, 0, []byte("alpha"))); err != nil {
		return err
	}
	if err := waitForSequence(httpBase, int(ch), 1); err != nil {
		return err
	}
	if _, err := c.Write(frameBytes(ch, 0, []byte("BETA!"))); err != nil { // same seq, different content
		return err
	}
	if err := waitForFailed(httpBase, int(ch)); err != nil {
		return err
	}
	st, _, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if !strings.Contains(st.FailReason, "conflict") {
		return fmt.Errorf("failReason=%q, want it to mention the conflict", st.FailReason)
	}
	if st.NextSequence != 1 {
		return fmt.Errorf("nextSequence=%d, want 1 (state frozen at failure)", st.NextSequence)
	}
	// More frames — valid or retransmitted — must not revive the channel.
	if _, err := c.Write(frameBytes(ch, 0, []byte("alpha"))); err != nil {
		return err
	}
	if _, err := c.Write(frameBytes(ch, 1, []byte("zzz"))); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	st2, _, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if st2.Status != "failed" || st2.FailReason != st.FailReason || st2.NextSequence != 1 {
		return fmt.Errorf("failed state not stable: %+v", st2)
	}
	return nil
}

// windowPath pushes a sequence beyond nextSequence+31 and requires a
// permanent window-overflow failure.
func windowPath(tcpAddr, httpBase string, ch uint8) error {
	c, err := dial(tcpAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(frameBytes(ch, 0, []byte("x"))); err != nil {
		return err
	}
	if err := waitForSequence(httpBase, int(ch), 1); err != nil {
		return err
	}
	if _, err := c.Write(frameBytes(ch, 33, []byte("y"))); err != nil { // 33-1=32 > 31
		return err
	}
	if err := waitForFailed(httpBase, int(ch)); err != nil {
		return err
	}
	st, _, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if !strings.Contains(st.FailReason, "window") {
		return fmt.Errorf("failReason=%q, want it to mention the window overflow", st.FailReason)
	}
	if st.NextSequence != 1 {
		return fmt.Errorf("nextSequence=%d, want 1", st.NextSequence)
	}
	return nil
}

func unknownChannel(httpBase string, id uint8) error {
	_, code, err := getStatus(httpBase, int(id))
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("GET unknown channel: http %d, want 404", code)
	}
	return nil
}

// checkpointPlanHappy registers a four-checkpoint plan against a live
// channel and drives 0..47 across concurrent, fragmented, out-of-order
// connections (one frame buffered far ahead before registration), asserting
// every checkpoint verifies on its own boundary and plan replay/conflict
// semantics.
func checkpointPlanHappy(tcpAddr, httpBase string, ch uint8) error {
	// Registration is only allowed for an existing channel: 404 first.
	if _, code, err := postPlan(httpBase, int(ch), planCheckpoints(9)); err != nil || code != http.StatusNotFound {
		return fmt.Errorf("plan on unknown channel: code=%d err=%v, want 404", code, err)
	}
	// Buffer frame 31 before registering (exactly at the window edge with
	// nextSequence=0): it stays pending while the earlier boundaries are
	// checked and must never leak into cumulative results before its own
	// boundary.
	c, err := dial(tcpAddr)
	if err != nil {
		return err
	}
	if _, err := c.Write(frameBytes(ch, 31, payloadFor(31))); err != nil {
		c.Close()
		return err
	}
	c.Close()
	if err := waitForChannelExists(httpBase, int(ch)); err != nil {
		return err
	}

	cps := planCheckpoints(9, 19, 31, 47)
	res, code, err := postPlan(httpBase, int(ch), cps)
	if err != nil || code != http.StatusOK {
		return fmt.Errorf("register plan: code=%d err=%v %+v", code, err, res)
	}
	for i, cs := range res.Checkpoints {
		if cs.State != "pending" || cs.Sequence != cps[i].Sequence {
			return fmt.Errorf("fresh plan checkpoint %d: %+v, want pending", i, cs)
		}
	}

	// Out-of-order delivery crossing the first three boundaries on three
	// connections; frame 47 is already buffered.
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	run := func(f func() error) {
		defer wg.Done()
		if err := f(); err != nil {
			errs <- err
		}
	}
	rev := func(lo, hi int) []int {
		var out []int
		for s := hi; s >= lo; s-- {
			out = append(out, s)
		}
		return out
	}
	wg.Add(3)
	go run(func() error { return senderByteByByte(tcpAddr, ch, rev(0, 9)...) })
	go run(func() error { return senderGarbageRange(tcpAddr, ch, 10, 19) })
	go run(func() error { return senderChunkedRange(tcpAddr, ch, 20, 31) })
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			return fmt.Errorf("sender: %w", e)
		}
	}
	if err := waitForSequence(httpBase, int(ch), 32); err != nil {
		return err
	}
	// Fill 32..47 reversed; 47 is buffered until the end and the final
	// boundary is only checked once it drains.
	if err := senderByteByByte(tcpAddr, ch, rev(32, 47)...); err != nil {
		return err
	}
	if err := waitForSequence(httpBase, int(ch), totalFrames); err != nil {
		return err
	}

	st, _, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if st.Status != "ok" {
		return fmt.Errorf("status=%q failReason=%q, want ok", st.Status, st.FailReason)
	}
	if len(st.Checkpoints) != 4 {
		return fmt.Errorf("checkpoints in status: %+v, want 4", st.Checkpoints)
	}
	for i, cs := range st.Checkpoints {
		if cs.Sequence != cps[i].Sequence || cs.State != "verified" {
			return fmt.Errorf("checkpoint %d: %+v, want verified at seq %d", i, cs, cps[i].Sequence)
		}
	}
	// Identical retry returns current states; a different plan is a 409.
	res2, code, err := postPlan(httpBase, int(ch), cps)
	if err != nil || code != http.StatusOK || !res2.Replayed {
		return fmt.Errorf("identical replay: code=%d err=%v replayed=%v", code, err, res2.Replayed)
	}
	for _, cs := range res2.Checkpoints {
		if cs.State != "verified" {
			return fmt.Errorf("replayed checkpoint %d state=%s", cs.Sequence, cs.State)
		}
	}
	different := planCheckpoints(9, 19, 31, 46)
	if _, code, err := postPlan(httpBase, int(ch), different); err != nil || code != http.StatusConflict {
		return fmt.Errorf("different plan: code=%d err=%v, want 409", code, err)
	}
	return nil
}

// checkpointMismatch registers a plan whose first checkpoint cannot match,
// drives the boundary frame over TCP and requires a permanent, stable
// failure naming the checkpoint and expected/actual results.
func checkpointMismatch(tcpAddr, httpBase string, ch uint8) error {
	// Bring the channel into existence with a buffered-ahead frame (next=0).
	if err := func() error {
		c, err := dial(tcpAddr)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write(frameBytes(ch, 3, payloadFor(3)))
		return err
	}(); err != nil {
		return err
	}
	if err := waitForChannelExists(httpBase, int(ch)); err != nil {
		return err
	}
	bad := checkpoint{Sequence: 0, ContiguousBytes: 999, SHA256: strings.Repeat("0", 64)}
	if res, code, err := postPlan(httpBase, int(ch), []checkpoint{bad, planCheckpoints(3)[0]}); err != nil || code != http.StatusOK {
		return fmt.Errorf("register plan: code=%d err=%v %+v", code, err, res)
	}
	c, err := dial(tcpAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(frameBytes(ch, 0, payloadFor(0))); err != nil {
		return err
	}
	if err := waitForFailed(httpBase, int(ch)); err != nil {
		return err
	}
	expectBytes, expectSum := cumulativeDigest(0)
	checkSt := func() error {
		st, code, err := getStatus(httpBase, int(ch))
		if err != nil {
			return err
		}
		if code != http.StatusOK || st.Status != "failed" {
			return fmt.Errorf("code=%d status=%q", code, st.Status)
		}
		if len(st.Checkpoints) != 2 || st.Checkpoints[0].State != "failed" ||
			st.Checkpoints[0].Sequence != 0 {
			return fmt.Errorf("checkpoint detail: %+v", st.Checkpoints)
		}
		fc := st.Checkpoints[0]
		if fc.ContiguousBytes != 999 || fc.SHA256 != strings.Repeat("0", 64) ||
			fc.ActualContiguousBytes != expectBytes || fc.ActualSHA256 != expectSum {
			return fmt.Errorf("expected/actual detail: %+v", fc)
		}
		if !strings.Contains(st.FailReason, "checkpoint") || !strings.Contains(st.FailReason, "0") {
			return fmt.Errorf("failReason=%q", st.FailReason)
		}
		if st.NextSequence != 1 {
			return fmt.Errorf("nextSequence=%d, want 1 (frozen)", st.NextSequence)
		}
		return nil
	}
	if err := checkSt(); err != nil {
		return err
	}
	// More frames must not change the state.
	if _, err := c.Write(frameBytes(ch, 1, payloadFor(1))); err != nil {
		return err
	}
	if _, err := c.Write(frameBytes(ch, 2, payloadFor(2))); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	if err := checkSt(); err != nil {
		return fmt.Errorf("after more frames: %w", err)
	}
	// An identical plan retry still returns the current (failed) states; a
	// different plan is rejected.
	res, code, err := postPlan(httpBase, int(ch), []checkpoint{bad, planCheckpoints(3)[0]})
	if err != nil || code != http.StatusOK || !res.Replayed ||
		len(res.Checkpoints) != 2 || res.Checkpoints[0].State != "failed" ||
		res.Checkpoints[1].State != "pending" {
		return fmt.Errorf("replay on failed channel: code=%d err=%v %+v", code, err, res)
	}
	if _, code, err := postPlan(httpBase, int(ch), planCheckpoints(0)); err != nil || code != http.StatusConflict {
		return fmt.Errorf("different plan on failed channel: code=%d err=%v, want 409", code, err)
	}
	return nil
}

// checkpointLate races the plan against inflow: once the first boundary is
// consumed the whole plan is refused (409), but a plan starting at the exact
// current nextSequence is still accepted and then verified.
func checkpointLate(tcpAddr, httpBase string, ch uint8) error {
	c, err := dial(tcpAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	for s := 0; s <= 3; s++ {
		if _, err := c.Write(frameBytes(ch, uint32(s), payloadFor(s))); err != nil {
			return err
		}
	}
	if err := waitForSequence(httpBase, int(ch), 4); err != nil {
		return err
	}
	// Boundary seq 2 has already been consumed: whole plan rejected.
	if _, code, err := postPlan(httpBase, int(ch), planCheckpoints(2, 5)); err != nil || code != http.StatusConflict {
		return fmt.Errorf("late plan: code=%d err=%v, want 409", code, err)
	}
	// And nothing was stored.
	st, _, err := getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if len(st.Checkpoints) != 0 {
		return fmt.Errorf("rejected plan was stored: %+v", st.Checkpoints)
	}
	// Boundary exactly at nextSequence (4) is still registerable.
	cps := planCheckpoints(4)
	if res, code, err := postPlan(httpBase, int(ch), cps); err != nil || code != http.StatusOK {
		return fmt.Errorf("boundary==next plan: code=%d err=%v %+v", code, err, res)
	}
	if _, err := c.Write(frameBytes(ch, 4, payloadFor(4))); err != nil {
		return err
	}
	if err := waitForSequence(httpBase, int(ch), 5); err != nil {
		return err
	}
	st, _, err = getStatus(httpBase, int(ch))
	if err != nil {
		return err
	}
	if st.Status != "ok" || len(st.Checkpoints) != 1 || st.Checkpoints[0].State != "verified" {
		return fmt.Errorf("boundary checkpoint not verified: %+v status=%q", st.Checkpoints, st.Status)
	}
	return nil
}

func waitHealthy(httpBase string) error {
	return waitFor("app health", func() (bool, error) {
		resp, err := http.Get(httpBase + "/healthz")
		if err != nil {
			return false, nil // not up yet: keep waiting
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK, nil
	})
}

func main() {
	tcpAddr := env("APP_TCP_ADDR", "app:9000")
	httpBase := env("APP_HTTP_ADDR", "http://app:8080")
	fmt.Printf("smoke target: tcp=%s http=%s\n", tcpAddr, httpBase)

	if err := waitHealthy(httpBase); err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		os.Exit(1)
	}
	happy, conflict, window, cpOK, cpBad, cpLate, unknown, err := pickChannels(httpBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("smoke channels: happy=%d conflict=%d window=%d checkpointOK=%d checkpointBad=%d checkpointLate=%d unknown=%d\n",
		happy, conflict, window, cpOK, cpBad, cpLate, unknown)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"unknown channel returns 404", func() error { return unknownChannel(httpBase, unknown) }},
		{"reordered/glued/byte-split frames yield identical digest", func() error { return happyPath(tcpAddr, httpBase, happy) }},
		{"content conflict fails channel with stable reason", func() error { return conflictPath(tcpAddr, httpBase, conflict) }},
		{"window overflow fails channel", func() error { return windowPath(tcpAddr, httpBase, window) }},
		{"checkpoint plan verifies across reordered multi-boundary inflow", func() error {
			return checkpointPlanHappy(tcpAddr, httpBase, cpOK)
		}},
		{"checkpoint mismatch fails channel with stable expected/actual", func() error {
			return checkpointMismatch(tcpAddr, httpBase, cpBad)
		}},
		{"checkpoint plan after a crossed boundary is refused", func() error {
			return checkpointLate(tcpAddr, httpBase, cpLate)
		}},
	}
	for _, s := range steps {
		fmt.Printf("[smoke] %-58s ", s.name)
		if err := s.fn(); err != nil {
			fmt.Println("FAIL")
			fmt.Fprintf(os.Stderr, "smoke step %q failed: %v\n", s.name, err)
			os.Exit(1)
		}
		fmt.Println("ok")
	}
	fmt.Println("SMOKE OK")
}
