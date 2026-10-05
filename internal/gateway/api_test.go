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

func postPlan(t *testing.T, s *Server, path, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.HTTPHandler().ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Code < 400 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %d body %q: %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func TestAPIPlanHappyReplayConflict(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 9, Seq: 0, Payload: []byte("hello")}) // next=1
	sum := sha256.Sum256([]byte("hello"))
	good := `{"checkpoints":[{"sequence":2,"contiguousBytes":5,"sha256":"` + hex.EncodeToString(sum[:]) + `"}]}`

	// First checkpoint seq 2 is ahead of nextSequence=1: accepted, pending.
	code, out := postPlan(t, s, "/api/channels/9/checkpoint-plan", good)
	if code != http.StatusOK {
		t.Fatalf("register code=%d body=%v", code, out)
	}
	cps := out["checkpoints"].([]any)
	if cps[0].(map[string]any)["state"] != "pending" {
		t.Fatalf("state=%v", cps)
	}
	// Identical retry replays current states.
	code, out = postPlan(t, s, "/api/channels/9/checkpoint-plan", good)
	if code != http.StatusOK || out["replayed"] != true {
		t.Fatalf("replay code=%d body=%v", code, out)
	}
	// Different content -> 409.
	bad := `{"checkpoints":[{"sequence":2,"contiguousBytes":6,"sha256":"` + hex.EncodeToString(sum[:]) + `"}]}`
	code, _ = postPlan(t, s, "/api/channels/9/checkpoint-plan", bad)
	if code != http.StatusConflict {
		t.Fatalf("different plan code=%d, want 409", code)
	}
}

func TestAPIPlanUnknownAndInvalid(t *testing.T) {
	s := NewServer()
	if code, _ := postPlan(t, s, "/api/channels/77/checkpoint-plan",
		`{"checkpoints":[{"sequence":0,"contiguousBytes":1,"sha256":"`+strings.Repeat("a", 64)+`"}]}`); code != http.StatusNotFound {
		t.Fatalf("unknown channel code=%d, want 404", code)
	}
	if code, _ := postPlan(t, s, "/api/channels/300/checkpoint-plan", "{}"); code != http.StatusBadRequest {
		t.Fatalf("bad id code=%d, want 400", code)
	}
	bads := []string{
		`{"checkpoints":[]}`,
		`{"checkpoints":[` + strings.Repeat(`{"sequence":0,"contiguousBytes":0,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`, 4) +
			`{"sequence":4,"contiguousBytes":0,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
		`{"checkpoints":[{"sequence":5,"contiguousBytes":0,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},` +
			`{"sequence":3,"contiguousBytes":0,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`,
		`{"checkpoints":[{"sequence":0,"contiguousBytes":0,"sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		`{"checkpoints":[{"sequence":0,"contiguousBytes":0,"sha256":"nothex"}]}`,
		`not json`,
	}
	for i, b := range bads {
		if code, _ := postPlan(t, s, "/api/channels/9/checkpoint-plan", b); code != http.StatusBadRequest {
			t.Fatalf("bad body %d code=%d, want 400: %s", i, code, b)
		}
	}
}

func TestAPIPlanCrossedBoundary(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 9, Seq: 0, Payload: []byte("hello")}) // next=1
	body := `{"checkpoints":[{"sequence":0,"contiguousBytes":5,"sha256":"` +
		strings.Repeat("0", 64) + `"}]}`
	code, _ := postPlan(t, s, "/api/channels/9/checkpoint-plan", body)
	if code != http.StatusConflict {
		t.Fatalf("crossed boundary code=%d, want 409", code)
	}
}

func TestAPIPlanOnFailedChannel(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 6, Seq: 0, Payload: []byte("a")})
	s.HandleFrame(Frame{Channel: 6, Seq: 0, Payload: []byte("b")}) // conflict -> failed
	body := `{"checkpoints":[{"sequence":1,"contiguousBytes":1,"sha256":"` + strings.Repeat("0", 64) + `"}]}`
	if code, _ := postPlan(t, s, "/api/channels/6/checkpoint-plan", body); code != http.StatusConflict {
		t.Fatalf("plan on failed channel code=%d, want 409", code)
	}
}

func TestAPIPlanMismatchFailsAndStatusStable(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 11, Seq: 5, Payload: []byte("z")}) // buffer ahead, next=0
	wrong := strings.Repeat("0", 64)
	body := `{"checkpoints":[{"sequence":0,"contiguousBytes":1,"sha256":"` + wrong + `"}]}`
	if code, _ := postPlan(t, s, "/api/channels/11/checkpoint-plan", body); code != http.StatusOK {
		t.Fatalf("register code=%d, want 200", code)
	}
	s.HandleFrame(Frame{Channel: 11, Seq: 0, Payload: []byte("x")}) // drains seq 0: mismatch
	code, st := getStatus(t, s, "/api/channels/11")
	if code != http.StatusOK || st.Status != "failed" {
		t.Fatalf("code=%d status=%q", code, st.Status)
	}
	wantSum := sha256.Sum256([]byte("x"))
	if len(st.Checkpoints) != 1 || st.Checkpoints[0].State != CheckpointFailed ||
		st.Checkpoints[0].Sequence != 0 || st.Checkpoints[0].SHA256 != wrong ||
		st.Checkpoints[0].ContiguousBytes != 1 ||
		st.Checkpoints[0].ActualContiguousBytes != 1 ||
		st.Checkpoints[0].ActualSHA256 != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("checkpoint detail: %+v", st.Checkpoints)
	}
	// More frames leave the failed checkpoint detail stable.
	s.HandleFrame(Frame{Channel: 11, Seq: 1, Payload: []byte("y")})
	_, st2 := getStatus(t, s, "/api/channels/11")
	if st2.Status != "failed" || st2.NextSequence != 1 ||
		st2.Checkpoints[0].State != CheckpointFailed ||
		st2.Checkpoints[0].ActualSHA256 != st.Checkpoints[0].ActualSHA256 {
		t.Fatalf("failed state unstable: %+v", st2)
	}
}
