package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	conn       net.Conn
	lastActive time.Time
	buffer     []byte
	mu         sync.Mutex
}

type Server struct {
	sessions sync.Map
	destHost string
	destPort string
	debug    bool
}

func NewServer(destHost, destPort string, debug bool) *Server {
	s := &Server{
		destHost: destHost,
		destPort: destPort,
		debug:    debug,
	}

	go s.cleanupSessions()
	return s
}

func (s *Server) cleanupSessions() {
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		s.sessions.Range(func(key, value interface{}) bool {
			session := value.(*Session)
			session.mu.Lock()
			if now.Sub(session.lastActive) > 5*time.Minute {
				session.conn.Close()
				s.sessions.Delete(key)
			}
			session.mu.Unlock()
			return true
		})
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		log.Printf("Received %s request from %s", r.Method, r.Header.Get("Cf-Connecting-Ip"))
	}

	// Verify Cloudflare connection
	cfConnecting := r.Header.Get("Cf-Connecting-Ip")
	if cfConnecting == "" {
		http.Error(w, "Direct access not allowed", http.StatusForbidden)
		return
	}

	// Set headers
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/octet-stream")

	sessionID := r.Header.Get("X-Ephemeral")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	var session *Session
	sessionInterface, exists := s.sessions.Load(sessionID)
	if !exists {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", s.destHost, s.destPort))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session = &Session{
			conn:       conn,
			lastActive: time.Now(),
			buffer:     make([]byte, 0),
		}
		s.sessions.Store(sessionID, session)
	} else {
		session = sessionInterface.(*Session)
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	session.lastActive = time.Now()

	if r.Method == http.MethodPost {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(data) > 0 {
			if s.debug {
				log.Printf("Writing %d bytes to connection", len(data))
			}
			_, err = session.conn.Write(data)
			if err != nil {
				if s.debug {
					log.Printf("Error writing to connection: %v", err)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		return
	}

	// For GET requests, read any available data
	buffer := make([]byte, 8192)
	var readData []byte

	for {
		session.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := session.conn.Read(buffer)
		if err != nil {
			if err != io.EOF && !err.(net.Error).Timeout() {
				if s.debug {
					log.Printf("Error reading from connection: %v", err)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			break
		}
		if n > 0 {
			if s.debug {
				log.Printf("Read %d bytes from connection", n)
			}
			readData = append(readData, buffer[:n]...)
		}
		if n < len(buffer) {
			break
		}
	}

	// Only encode and send if we have data
	if len(readData) > 0 {
		encoded := hex.EncodeToString(readData)
		if s.debug {
			log.Printf("Sending %d bytes (encoded: %d bytes)", len(readData), len(encoded))
		}
		w.Write([]byte(encoded))
	}
}

func main() {
	var port int
	var dest string
	var debug bool

	flag.IntVar(&port, "p", 8080, "Port to listen on")
	flag.StringVar(&dest, "d", "", "Destination address (host:port)")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	if dest == "" {
		log.Fatal("Destination address (-d) is required")
	}

	destHost, destPort, err := net.SplitHostPort(dest)
	if err != nil {
		log.Fatalf("Invalid destination address: %v", err)
	}

	server := NewServer(destHost, destPort, debug)

	log.Printf("DarkFlare server running on port %d", port)
	log.Printf("Forwarding to %s:%s", destHost, destPort)

	http.HandleFunc("/", server.handleRequest)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
