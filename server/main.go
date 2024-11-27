// Copyright (c) Barrett Lyon
// blyon@blyon.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
	sessions    sync.Map
	destHost    string
	destPort    string
	debug       bool
	appCommand  string
	isAppMode   bool
	allowDirect bool
}

func NewServer(destHost, destPort string, appCommand string, debug bool, allowDirect bool) *Server {
	s := &Server{
		destHost:    destHost,
		destPort:    destPort,
		debug:       debug,
		appCommand:  appCommand,
		isAppMode:   appCommand != "",
		allowDirect: allowDirect,
	}

	if s.isAppMode && s.debug {
		log.Printf("Starting in application mode with command: %s", appCommand)
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

func (s *Server) handleApplication(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		log.Printf("Handling application request from %s", r.Header.Get("Cf-Connecting-Ip"))
	}

	parts := strings.Fields(s.appCommand)
	if len(parts) == 0 {
		http.Error(w, "Invalid application command", http.StatusInternalServerError)
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = os.Environ()

	if s.debug {
		log.Printf("Launching application: %s", s.appCommand)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Failed to create stderr pipe: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start application: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle stdout in a goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stdout: %s", scanner.Text())
			}
		}
		if err := scanner.Err(); err != nil && s.debug {
			log.Printf("Error reading stdout: %v", err)
		}
	}()

	// Handle stderr in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stderr: %s", scanner.Text())
			}
		}
		if err := scanner.Err(); err != nil && s.debug {
			log.Printf("Error reading stderr: %v", err)
		}
	}()

	if err := cmd.Wait(); err != nil {
		if s.debug {
			log.Printf("Application exited with error: %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if s.isAppMode {
		s.handleApplication(w, r)
		return
	}

	if s.debug {
		log.Printf("Request: %s %s from %s",
			r.Method,
			r.URL.Path,
			r.Header.Get("Cf-Connecting-Ip"),
		)
		log.Printf("Headers: %+v", r.Header)
	}

	// Verify Cloudflare connection
	cfConnecting := r.Header.Get("Cf-Connecting-Ip")
	if cfConnecting == "" && !s.allowDirect {
		http.Error(w, "Direct access not allowed", http.StatusForbidden)
		return
	}

	// Set Apache-like headers
	w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
	w.Header().Set("X-Powered-By", "PHP/7.4.33")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Cache control headers
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/octet-stream")

	sessionID := r.Header.Get("X-Ephemeral")
	if sessionID == "" {
		if s.debug {
			log.Printf("Error: Missing session ID from %s", r.Header.Get("Cf-Connecting-Ip"))
		}
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
			if s.debug {
				log.Printf("Error reading request body: %v", err)
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(data) > 0 {
			if s.debug {
				log.Printf("POST: Writing %d bytes to connection for session %s",
					len(data),
					sessionID[:8], // First 8 chars of session ID for brevity
				)
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
				log.Printf("GET: Read %d bytes from connection for session %s",
					n,
					sessionID[:8],
				)
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
			log.Printf("Response: Sending %d bytes (encoded: %d bytes) for session %s path %s",
				len(readData),
				len(encoded),
				sessionID[:8],
				r.URL.Path,
			)
		}
		w.Write([]byte(encoded))
	} else if s.debug {
		log.Printf("Response: No data to send for session %s path %s",
			sessionID[:8],
			r.URL.Path,
		)
	}
}

func main() {
	var port int
	var dest string
	var debug bool
	var appCommand string
	var allowDirect bool

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DarkFlare Server - TCP-over-CDN tunnel server component\n")
		fmt.Fprintf(os.Stderr, "(c) 2024 Barrett Lyon - blyon@blyon.com\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -p        Port to listen on (default: 8080)\n")
		fmt.Fprintf(os.Stderr, "  -d        Destination address in host:port format\n")
		fmt.Fprintf(os.Stderr, "            Example: localhost:22 for SSH forwarding\n\n")
		fmt.Fprintf(os.Stderr, "  -a        Application mode: launches a command instead of forwarding\n")
		fmt.Fprintf(os.Stderr, "            Example: 'sshd -i' or 'pppd noauth'\n")
		fmt.Fprintf(os.Stderr, "            Note: Cannot be used with -d flag\n\n")
		fmt.Fprintf(os.Stderr, "  -debug    Enable debug logging\n")
		fmt.Fprintf(os.Stderr, "  -o        Allow direct connections without Cloudflare headers\n")
		fmt.Fprintf(os.Stderr, "            Warning: Not recommended for production use\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  SSH forwarding:\n")
		fmt.Fprintf(os.Stderr, "    %s -d localhost:22 -p 8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Run SSH daemon directly:\n")
		fmt.Fprintf(os.Stderr, "    %s -a \"sshd -i\" -p 8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Debug mode with direct access:\n")
		fmt.Fprintf(os.Stderr, "    %s -d localhost:22 -p 8080 -debug -o\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "For more information: https://github.com/blyon/darkflare\n")
	}

	flag.IntVar(&port, "p", 8080, "")
	flag.StringVar(&dest, "d", "", "")
	flag.StringVar(&appCommand, "a", "", "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.BoolVar(&allowDirect, "o", false, "")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	if dest != "" && appCommand != "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot specify both -d and -a options\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if dest == "" && appCommand == "" {
		fmt.Fprintf(os.Stderr, "Error: Must specify either destination (-d) or application (-a)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	var destHost, destPort string
	if dest != "" {
		var err error
		destHost, destPort, err = net.SplitHostPort(dest)
		if err != nil {
			log.Fatalf("Invalid destination address: %v", err)
		}
	}

	server := NewServer(destHost, destPort, appCommand, debug, allowDirect)

	log.Printf("DarkFlare server running on port %d", port)
	if allowDirect {
		log.Printf("Warning: Direct connections allowed (no Cloudflare required)")
	}
	if appCommand != "" {
		log.Printf("Running in application mode with command: %s", appCommand)
	} else {
		log.Printf("Running in proxy mode, forwarding to %s:%s", destHost, destPort)
	}

	http.HandleFunc("/", server.handleRequest)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
