package gateway

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Server owns the channel registry and serves TCP frame streams and the
// HTTP status API.
type Server struct {
	mu       sync.Mutex
	channels map[uint8]*Channel
}

// NewServer returns an empty server.
func NewServer() *Server {
	return &Server{channels: make(map[uint8]*Channel)}
}

func (s *Server) channel(id uint8) (*Channel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.channels[id]
	return c, ok
}

func (s *Server) channelOrCreate(id uint8) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.channels[id]
	if !ok {
		c = NewChannel(id)
		s.channels[id] = c
		log.Printf("channel %d created", id)
	}
	return c
}

// HandleFrame routes one decoded frame to its channel.
func (s *Server) HandleFrame(f Frame) {
	s.channelOrCreate(f.Channel).Handle(f)
}

// ServeTCP accepts connections on ln until it is closed; each connection is
// parsed independently and frames are dispatched to shared channels.
func (s *Server) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("tcp connection from %s", conn.RemoteAddr())
	p := &Parser{}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			for _, f := range p.Feed(buf[:n]) {
				s.HandleFrame(f)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("tcp read %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
	}
}

// HTTPHandler returns the status API handler.
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /api/channels/{id}", s.handleChannelStatus)
	mux.HandleFunc("POST /api/channels/{id}/checkpoint-plan", s.handleCheckpointPlan)
	return mux
}

func (s *Server) handleChannelStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 8)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel id: want integer 0-255")
		return
	}
	c, ok := s.channel(uint8(id))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown channel")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.Status())
}

// maxPlanCheckpoints bounds how many checkpoints one plan may carry.
const maxPlanCheckpoints = 4

type checkpointPlanRequest struct {
	Checkpoints []struct {
		Sequence        uint32 `json:"sequence"`
		ContiguousBytes int64  `json:"contiguousBytes"`
		SHA256          string `json:"sha256"`
	} `json:"checkpoints"`
}

type checkpointPlanResponse struct {
	Checkpoints []CheckpointStatus `json:"checkpoints"`
	// Replayed reports that an identical plan already existed; it is purely
	// informational (the client gets current states either way).
	Replayed bool `json:"replayed"`
}

// handleCheckpointPlan registers (or idempotently replays) a checkpoint plan.
func (s *Server) handleCheckpointPlan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 8)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel id: want integer 0-255")
		return
	}
	var req checkpointPlanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	plan, err := validatePlan(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, ok := s.channel(uint8(id))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown channel")
		return
	}
	res, err := c.RegisterPlan(plan)
	if err != nil {
		switch {
		case errors.Is(err, ErrChannelFailed):
			writeError(w, http.StatusConflict, "channel is permanently failed")
		case errors.Is(err, ErrCheckpointPlanLate):
			writeError(w, http.StatusConflict, "inflow already crossed the first checkpoint boundary")
		case errors.Is(err, ErrCheckpointPlanExists):
			writeError(w, http.StatusConflict, "channel already has a different checkpoint plan")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(checkpointPlanResponse{Checkpoints: res.Statuses, Replayed: res.Replayed})
}

// validatePlan enforces the request shape: 1..4 checkpoints, strictly
// increasing end-frame sequences, non-negative byte counts and lowercase
// hex SHA-256 digests.
func validatePlan(req checkpointPlanRequest) ([]Checkpoint, error) {
	n := len(req.Checkpoints)
	if n < 1 || n > maxPlanCheckpoints {
		return nil, fmt.Errorf("checkpoints must contain 1-%d entries, got %d", maxPlanCheckpoints, n)
	}
	plan := make([]Checkpoint, n)
	for i, cp := range req.Checkpoints {
		if i > 0 && cp.Sequence <= plan[i-1].Sequence {
			return nil, fmt.Errorf("checkpoints[%d].sequence must be strictly greater than the previous one", i)
		}
		if cp.ContiguousBytes < 0 {
			return nil, fmt.Errorf("checkpoints[%d].contiguousBytes must be non-negative", i)
		}
		if len(cp.SHA256) != 64 || cp.SHA256 != strings.ToLower(cp.SHA256) {
			return nil, fmt.Errorf("checkpoints[%d].sha256 must be 64 lowercase hex characters", i)
		}
		if _, err := hex.DecodeString(cp.SHA256); err != nil {
			return nil, fmt.Errorf("checkpoints[%d].sha256 is not valid hex: %w", i, err)
		}
		plan[i] = Checkpoint{
			Sequence:        cp.Sequence,
			ContiguousBytes: cp.ContiguousBytes,
			SHA256:          cp.SHA256,
		}
	}
	return plan, nil
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
