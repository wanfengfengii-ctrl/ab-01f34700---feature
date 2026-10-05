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
	Channel         uint8    `json:"channel"`
	Status          string   `json:"status"`
	NextSequence    uint32   `json:"nextSequence"`
	SeenSequences   []uint32 `json:"seenSequences"`
	ContiguousBytes uint64   `json:"contiguousBytes"`
	SHA256          string   `json:"sha256"`
	FailReason      string   `json:"failReason"`
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
	for _, s := range []int{15, 10, 19, 12, 17, 11, 14, 18, 13, 16} {
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
	for s := 20; s <= 31; s++ {
		b.Write(frameBytes(ch, uint32(s), payloadFor(s)))
	}
	b.Write(frameBytes(ch, 5, payloadFor(5)))
	b.Write(frameBytes(ch, 25, payloadFor(25)))
	return writeChunks(c, b.Bytes(), func(off int) int { return 1 + (off*11)%64 })
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

// pickChannels finds four currently-unknown channels: three to exercise
// (happy path, conflict, window overflow) and one that must stay unknown
// for the 404 check. This keeps verify re-runnable against a long-lived
// gateway that still holds state from previous runs.
func pickChannels(base string) (happy, conflict, window, unknown uint8, err error) {
	off := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(256)
	var free []uint8
	for i := 0; i < 256 && len(free) < 4; i++ {
		id := uint8((off + i) % 256)
		_, code, e := getStatus(base, int(id))
		if e != nil {
			return 0, 0, 0, 0, fmt.Errorf("probe channel %d: %w", id, e)
		}
		if code == http.StatusNotFound {
			free = append(free, id)
		}
	}
	if len(free) < 4 {
		return 0, 0, 0, 0, fmt.Errorf("need 4 unused channels, found %d", len(free))
	}
	return free[0], free[1], free[2], free[3], nil
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
	happy, conflict, window, unknown, err := pickChannels(httpBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("smoke channels: happy=%d conflict=%d window=%d unknown=%d\n",
		happy, conflict, window, unknown)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"unknown channel returns 404", func() error { return unknownChannel(httpBase, unknown) }},
		{"reordered/glued/byte-split frames yield identical digest", func() error { return happyPath(tcpAddr, httpBase, happy) }},
		{"content conflict fails channel with stable reason", func() error { return conflictPath(tcpAddr, httpBase, conflict) }},
		{"window overflow fails channel", func() error { return windowPath(tcpAddr, httpBase, window) }},
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
