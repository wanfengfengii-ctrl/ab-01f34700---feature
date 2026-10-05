package gateway

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
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

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
