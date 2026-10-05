package gateway

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// mkFrame builds a wire-format frame for tests.
func mkFrame(ch uint8, seq uint32, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(SyncWord)
	b.WriteByte(ch)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], seq)
	b.Write(tmp[:])
	binary.BigEndian.PutUint16(tmp[:], uint16(len(payload)))
	b.Write(tmp[:2])
	b.Write(payload)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc32.ChecksumIEEE(b.Bytes()[4:]))
	b.Write(c[:])
	return b.Bytes()
}

// feedInChunks feeds data to p in chunk-sized pieces and collects frames.
func feedInChunks(p *Parser, data []byte, chunk int) []Frame {
	var out []Frame
	for i := 0; i < len(data); i += chunk {
		end := i + chunk
		if end > len(data) {
			end = len(data)
		}
		out = append(out, p.Feed(data[i:end])...)
	}
	return out
}

func TestParserSingleFrame(t *testing.T) {
	p := &Parser{}
	frames := p.Feed(mkFrame(3, 0, []byte("hello")))
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	f := frames[0]
	if f.Channel != 3 || f.Seq != 0 || !bytes.Equal(f.Payload, []byte("hello")) {
		t.Fatalf("bad frame: %+v", f)
	}
}

func TestParserByteByByte(t *testing.T) {
	var stream []byte
	stream = append(stream, mkFrame(1, 0, []byte("aaa"))...)
	stream = append(stream, mkFrame(2, 7, bytes.Repeat([]byte{0x5A}, 100))...)
	frames := feedInChunks(&Parser{}, stream, 1)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].Seq != 0 || frames[1].Seq != 7 || len(frames[1].Payload) != 100 {
		t.Fatalf("bad frames: %+v", frames)
	}
}

func TestParserCoalescedWithGarbage(t *testing.T) {
	var stream []byte
	stream = append(stream, 0x00, 0xFF, 0x1A, 0x13, 0x37) // garbage, lone 0x1A is not a sync
	stream = append(stream, mkFrame(1, 0, []byte("one"))...)
	stream = append(stream, mkFrame(1, 1, []byte("two"))...)
	for _, chunk := range []int{7, 4096} {
		frames := feedInChunks(&Parser{}, stream, chunk)
		if len(frames) != 2 {
			t.Fatalf("chunk=%d: got %d frames, want 2", chunk, len(frames))
		}
		if string(frames[0].Payload) != "one" || string(frames[1].Payload) != "two" {
			t.Fatalf("chunk=%d: bad payloads %q %q", chunk, frames[0].Payload, frames[1].Payload)
		}
	}
}

func TestParserBadCRCResync(t *testing.T) {
	bad := mkFrame(1, 1, []byte("badbad"))
	bad[len(bad)-1] ^= 0xFF // corrupt CRC
	var stream []byte
	stream = append(stream, bad...)
	stream = append(stream, mkFrame(1, 0, []byte("first"))...)
	stream = append(stream, mkFrame(1, 2, []byte("second"))...)
	frames := feedInChunks(&Parser{}, stream, 5)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2 (bad CRC candidate must be skipped)", len(frames))
	}
	if frames[0].Seq != 0 || frames[1].Seq != 2 {
		t.Fatalf("bad seqs: %d %d", frames[0].Seq, frames[1].Seq)
	}
}

func TestParserIllegalLengthResync(t *testing.T) {
	var stream []byte
	// Candidate with length 0 (illegal), glued to junk.
	stream = append(stream, SyncWord...)
	stream = append(stream, 9, 0, 0, 0, 1, 0, 0)
	stream = append(stream, 0xAA, 0xBB, 0xCC)
	// Candidate with length 2000 > 1024 (illegal), glued to junk.
	stream = append(stream, SyncWord...)
	stream = append(stream, 9, 0, 0, 0, 2, 0x07, 0xD0)
	stream = append(stream, 0x01, 0x02, 0x03)
	// A real frame right behind them.
	stream = append(stream, mkFrame(9, 3, []byte("real"))...)
	frames := feedInChunks(&Parser{}, stream, 3)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].Seq != 3 || string(frames[0].Payload) != "real" {
		t.Fatalf("bad frame: %+v", frames[0])
	}
}

func TestParserPartialSyncSuffixKept(t *testing.T) {
	frame := mkFrame(2, 5, []byte("data"))
	p := &Parser{}
	if got := p.Feed([]byte{0x99, 0x1A, 0xCF}); len(got) != 0 { // garbage ending in partial sync
		t.Fatalf("early frames: %v", got)
	}
	frames := p.Feed(frame[2:]) // completes the sync word, then the frame
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].Seq != 5 || string(frames[0].Payload) != "data" {
		t.Fatalf("bad frame: %+v", frames[0])
	}
}

func TestParserFragmentedHeaderAndCRC(t *testing.T) {
	frame := mkFrame(4, 9, bytes.Repeat([]byte{0x7E}, 1024)) // max-size payload
	for _, chunk := range []int{1, 2, 3, 11, 13} {
		frames := feedInChunks(&Parser{}, frame, chunk)
		if len(frames) != 1 {
			t.Fatalf("chunk=%d: got %d frames, want 1", chunk, len(frames))
		}
		if len(frames[0].Payload) != 1024 {
			t.Fatalf("chunk=%d: payload len %d", chunk, len(frames[0].Payload))
		}
	}
}
