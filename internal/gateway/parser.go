package gateway

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

// SyncWord marks the start of every frame: 1A CF FC 1D.
var SyncWord = []byte{0x1A, 0xCF, 0xFC, 0x1D}

const (
	// MaxPayload is the largest legal payload length in bytes.
	MaxPayload = 1024
	// headerLen = sync(4) + channel(1) + sequence(4) + length(2).
	headerLen = 11
	crcLen    = 4
)

// Frame is one decoded telemetry frame.
type Frame struct {
	Channel uint8
	Seq     uint32
	Payload []byte
}

// Parser incrementally extracts frames from a TCP byte stream. Bytes may
// arrive fragmented (down to a single byte per read) or coalesced (several
// frames plus garbage in one read); Feed handles both. Candidates with an
// illegal length or a bad CRC are discarded and scanning resumes one byte
// past the candidate's sync word, so a valid frame glued to a corrupt one
// is still recovered.
type Parser struct {
	buf []byte
}

// Feed appends data to the stream and returns every frame completed by it.
func (p *Parser) Feed(data []byte) []Frame {
	p.buf = append(p.buf, data...)
	var frames []Frame
	for {
		f, progress := p.step()
		if !progress {
			break
		}
		if f != nil {
			frames = append(frames, *f)
		}
	}
	return frames
}

// step makes one parsing attempt. It reports progress=true when the buffer
// was advanced (a frame was produced, or a candidate was discarded) and
// progress=false when more bytes are needed.
func (p *Parser) step() (frame *Frame, progress bool) {
	i := bytes.Index(p.buf, SyncWord)
	if i < 0 {
		// No sync word: drop everything except a trailing partial sync word.
		p.buf = p.buf[len(p.buf)-partialSyncLen(p.buf):]
		return nil, false
	}
	p.buf = p.buf[i:]
	if len(p.buf) < headerLen {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(p.buf[9:11]))
	if length < 1 || length > MaxPayload {
		// Illegal length: discard this candidate, keep scanning for sync.
		p.buf = p.buf[1:]
		return nil, true
	}
	total := headerLen + length + crcLen
	if len(p.buf) < total {
		return nil, false
	}
	body := p.buf[4 : headerLen+length] // channel .. payload
	want := binary.BigEndian.Uint32(p.buf[headerLen+length : total])
	if crc32.ChecksumIEEE(body) != want {
		// Bad CRC: discard this candidate, keep scanning for sync.
		p.buf = p.buf[1:]
		return nil, true
	}
	f := &Frame{
		Channel: p.buf[4],
		Seq:     binary.BigEndian.Uint32(p.buf[5:9]),
		Payload: append([]byte(nil), p.buf[headerLen:headerLen+length]...),
	}
	p.buf = p.buf[total:]
	return f, true
}

// partialSyncLen returns the length of the longest suffix of buf that is a
// prefix of the sync word (and therefore must be kept for the next Feed).
func partialSyncLen(buf []byte) int {
	max := len(buf)
	if max > len(SyncWord)-1 {
		max = len(SyncWord) - 1
	}
	for k := max; k > 0; k-- {
		if bytes.Equal(buf[len(buf)-k:], SyncWord[:k]) {
			return k
		}
	}
	return 0
}
