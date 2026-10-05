package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postPlan(t *testing.T, s *Server, path, body string) (int, CheckpointPlanStatus) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.HTTPHandler().ServeHTTP(rec, req)
	var st CheckpointPlanStatus
	if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("decode response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, st
}

func planBody(cps ...Checkpoint) string {
	b, _ := json.Marshal(checkpointPlanRequest{Checkpoints: cps})
	return string(b)
}

func TestAPIPlanUnknownChannel404(t *testing.T) {
	s := NewServer()
	body := planBody(Checkpoint{Sequence: 0, ContiguousBytes: 1, SHA256: strings.Repeat("a", 64)})
	if code, _ := postPlan(t, s, "/api/channels/99/checkpoint-plan", body); code != http.StatusNotFound {
		t.Fatalf("code=%d, want 404 (registration must not create a channel)", code)
	}
	// Still unknown to GET afterwards.
	if code, _ := getStatus(t, s, "/api/channels/99"); code != http.StatusNotFound {
		t.Fatalf("GET code=%d, want 404", code)
	}
}

func TestAPIPlanInvalidID400(t *testing.T) {
	s := NewServer()
	if code, _ := postPlan(t, s, "/api/channels/x/checkpoint-plan", "{}"); code != http.StatusBadRequest {
		t.Fatalf("code=%d, want 400", code)
	}
}

func TestAPIPlanInvalidBody400(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 3, Seq: 0, Payload: []byte("x")})
	bodies := []string{
		`{`,
		`{"checkpoints":[]}`,
		`{"checkpoints":[{"sequence":0,"contiguousBytes":0,"sha256":"zzz"}]}`,
		// 64 uppercase hex characters: lowercase is required.
		fmt.Sprintf(`{"checkpoints":[{"sequence":0,"contiguousBytes":1,"sha256":%q}]}`, strings.Repeat("A", 64)),
	}
	for _, body := range bodies {
		if code, _ := postPlan(t, s, "/api/channels/3/checkpoint-plan", body); code != http.StatusBadRequest {
			t.Fatalf("body=%q code=%d, want 400", body, code)
		}
	}
}

func TestAPIPlanRegisterRetryAndConflict(t *testing.T) {
	s := NewServer()
	p0 := []byte("frame-0")
	s.HandleFrame(Frame{Channel: 4, Seq: 0, Payload: p0})
	sum0 := sha256.Sum256(p0)
	cp := Checkpoint{Sequence: 0, ContiguousBytes: uint64(len(p0)), SHA256: hex.EncodeToString(sum0[:])}

	code, st := postPlan(t, s, "/api/channels/4/checkpoint-plan", planBody(cp))
	if code != http.StatusCreated {
		t.Fatalf("first register code=%d, want 201", code)
	}
	if len(st.Checkpoints) != 1 || st.Checkpoints[0].State != cpMatched {
		t.Fatalf("first register state: %+v", st)
	}

	// Identical content retried: 200 + current states.
	code, st = postPlan(t, s, "/api/channels/4/checkpoint-plan", planBody(cp))
	if code != http.StatusOK {
		t.Fatalf("retry code=%d, want 200", code)
	}
	if st.Checkpoints[0].State != cpMatched {
		t.Fatalf("retry state: %+v", st)
	}

	// Different content: 409.
	other := Checkpoint{Sequence: 0, ContiguousBytes: uint64(len(p0)), SHA256: strings.Repeat("0", 64)}
	if code, _ := postPlan(t, s, "/api/channels/4/checkpoint-plan", planBody(other)); code != http.StatusConflict {
		t.Fatalf("conflict code=%d, want 409", code)
	}

	// The original plan still stands.
	_, gst := getStatus(t, s, "/api/channels/4")
	if gst.Status != "ok" || gst.CheckpointPlan == nil ||
		gst.CheckpointPlan.Checkpoints[0].State != cpMatched {
		t.Fatalf("original plan altered: %+v", gst)
	}
}

func TestAPIPlanBoundaryAlreadyCrossed409(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 8, Seq: 0, Payload: []byte("x")})
	s.HandleFrame(Frame{Channel: 8, Seq: 1, Payload: []byte("yy")}) // next=2
	cp := Checkpoint{Sequence: 0, ContiguousBytes: 1, SHA256: strings.Repeat("a", 64)}
	if code, _ := postPlan(t, s, "/api/channels/8/checkpoint-plan", planBody(cp)); code != http.StatusConflict {
		t.Fatalf("code=%d, want 409", code)
	}
}

func TestAPIPlanFailedChannel409(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 9, Seq: 0, Payload: []byte("a")})
	s.HandleFrame(Frame{Channel: 9, Seq: 0, Payload: []byte("b")})
	cp := Checkpoint{Sequence: 0, ContiguousBytes: 1, SHA256: strings.Repeat("a", 64)}
	if code, _ := postPlan(t, s, "/api/channels/9/checkpoint-plan", planBody(cp)); code != http.StatusConflict {
		t.Fatalf("code=%d, want 409", code)
	}
}

func TestAPIPlanMismatchDetailsInStatus(t *testing.T) {
	s := NewServer()
	s.HandleFrame(Frame{Channel: 10, Seq: 0, Payload: []byte("abc")})
	bad := Checkpoint{Sequence: 0, ContiguousBytes: 3, SHA256: strings.Repeat("f", 64)}
	if code, _ := postPlan(t, s, "/api/channels/10/checkpoint-plan", planBody(bad)); code != http.StatusCreated {
		t.Fatalf("code=%d, want 201", code)
	}
	// Crossing the boundary on the next frame fails the channel.
	s.HandleFrame(Frame{Channel: 10, Seq: 1, Payload: []byte("d")})
	_, gst := getStatus(t, s, "/api/channels/10")
	if gst.Status != "failed" {
		t.Fatalf("status=%q, want failed", gst.Status)
	}
	got := gst.CheckpointPlan.Checkpoints[0]
	if got.State != cpMismatch || got.Sequence != 0 ||
		got.ActualContiguousBytes != 3 || got.ActualSHA256 != hex.EncodeToString(sha256.New().Sum(nil)) {
		t.Fatalf("mismatch entry: %+v", got)
	}
	wantSHA := fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))
	if got.ActualSHA256 != wantSHA {
		t.Fatalf("actual sha=%s, want %s", got.ActualSHA256, wantSHA)
	}
	if !bytes.Contains([]byte(gst.FailReason), []byte("checkpoint mismatch")) {
		t.Fatalf("failReason=%q", gst.FailReason)
	}
}
