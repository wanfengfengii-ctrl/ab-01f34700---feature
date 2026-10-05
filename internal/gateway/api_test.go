package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getStatus(t *testing.T, s *Server, path string) (int, ChannelStatus) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	s.HTTPHandler().ServeHTTP(rec, req)
	var st ChannelStatus
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, st
}

func TestAPIUnknownChannel404(t *testing.T) {
	s := NewServer()
	code, _ := getStatus(t, s, "/api/channels/42")
	if code != http.StatusNotFound {
		t.Fatalf("code=%d, want 404", code)
	}
}

func TestAPIInvalidChannelID(t *testing.T) {
	s := NewServer()
	for _, id := range []string{"abc", "-1", "256", "1.5"} {
		if code, _ := getStatus(t, s, "/api/channels/"+id); code != http.StatusBadRequest {
			t.Fatalf("id=%q code=%d, want 400", id, code)
		}
	}
}

func TestAPIChannelStatus(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 5, Seq: 0, Payload: []byte("hello")})
	s.HandleFrame(Frame{Channel: 5, Seq: 2, Payload: []byte("two")})
	code, st := getStatus(t, s, "/api/channels/5")
	if code != http.StatusOK {
		t.Fatalf("code=%d", code)
	}
	sum := sha256.Sum256([]byte("hello"))
	want := ChannelStatus{
		Channel:         5,
		Status:          "ok",
		NextSequence:    1,
		SeenSequences:   []uint32{0, 2},
		ContiguousBytes: 5,
		SHA256:          hex.EncodeToString(sum[:]),
	}
	if st.Channel != want.Channel || st.Status != want.Status ||
		st.NextSequence != want.NextSequence || st.ContiguousBytes != want.ContiguousBytes ||
		st.SHA256 != want.SHA256 {
		t.Fatalf("got %+v, want %+v", st, want)
	}
	if len(st.SeenSequences) != 2 || st.SeenSequences[0] != 0 || st.SeenSequences[1] != 2 {
		t.Fatalf("seen=%v", st.SeenSequences)
	}
}

func TestAPIFailedChannel(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 6, Seq: 0, Payload: []byte("a")})
	s.HandleFrame(Frame{Channel: 6, Seq: 0, Payload: []byte("b")})
	code, st := getStatus(t, s, "/api/channels/6")
	if code != http.StatusOK {
		t.Fatalf("code=%d", code)
	}
	if st.Status != "failed" || !strings.Contains(st.FailReason, "conflict") {
		t.Fatalf("status=%q reason=%q", st.Status, st.FailReason)
	}
}

func TestAPIHealthz(t *testing.T) {
	s := NewServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
}
