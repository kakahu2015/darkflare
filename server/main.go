package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	directMode  bool
}

func NewServer(destHost, destPort string, appCommand string, debug bool, directMode bool) *Server {
	s := &Server{
		destHost:   destHost,
		destPort:   destPort,
		debug:      debug,
		appCommand: appCommand,
		isAppMode:  appCommand != "",
		directMode: directMode,
	}

	if s.debug {
		if s.directMode {
			log.Printf("Starting in direct connection mode")
		}
		if s.isAppMode {
			log.Printf("Starting in application mode with command: %s", appCommand)
		}
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
				if s.debug {
					log.Printf("Cleaned up inactive session: %v", key)
				}
			}
			session.mu.Unlock()
			return true
		})
	}
}

func (s *Server) handleApplication(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		log.Printf("Handling application request from %s", r.RemoteAddr)
	}

	parts := strings.Fields(s.appCommand)
	if len(parts) == 0 {
		http.Error(w, "Invalid application command", http.StatusInternalServerError)
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = os.Environ()

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

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stdout: %s", scanner.Text())
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stderr: %s", scanner.Text())
			}
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
    ////////////////////////////////////
	username, password, ok := r.BasicAuth()
    if !ok || username != s.username || password != s.password {
        w.Header().Set("Location", "https://book.kakahu.org")
        w.WriteHeader(http.StatusFound) 
        return
    }
	////////////////////////////////////

	if s.isAppMode {
		s.handleApplication(w, r)
		return
	}

	if s.debug {
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("Headers: %+v", r.Header)
	}

	var sessionID string
	if s.directMode {
		sessionID = r.Header.Get("X-Session-ID")
		if sessionID == "" {
			// 在直连模式下使用客户端地址作为会话ID
			sessionID = fmt.Sprintf("%x", sha256.Sum256([]byte(r.RemoteAddr)))
		}
	} else {
		// CDN模式下的会话ID处理
		sessionID = r.Header.Get("Cf-Ray")
		if sessionID == "" {
			sessionID = r.Header.Get("Cf-Connecting-Ip")
		}
		if sessionID == "" {
			sessionID = r.Header.Get("X-Ephemeral")
		}
		
		// 验证CDN请求
		cfConnecting := r.Header.Get("Cf-Connecting-Ip")
		if cfConnecting == "" && !s.directMode {
			http.Error(w, "Direct access not allowed in CDN mode", http.StatusForbidden)
			return
		}
	}

	if sessionID == "" {
		if s.debug {
			log.Printf("Error: Missing session ID from %s", r.RemoteAddr)
		}
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// 设置基本响应头
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/octet-stream")

	// 在CDN模式下添加伪装头
	if !s.directMode {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.33")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
	}

	var session *Session
	sessionInterface, exists := s.sessions.Load(sessionID)
	if !exists {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", s.destHost, s.destPort))
		if err != nil {
			log.Printf("Failed to establish connection: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session = &Session{
			conn:       conn,
			lastActive: time.Now(),
			buffer:     make([]byte, 0),
		}
		s.sessions.Store(sessionID, session)
		if s.debug {
			log.Printf("Created new session: %s", sessionID)
		}
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
					len(data), sessionID[:8])
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
					n, sessionID[:8])
			}
			readData = append(readData, buffer[:n]...)
		}
		if n < len(buffer) {
			break
		}
	}

	if len(readData) > 0 {
		encoded := hex.EncodeToString(readData)
		if s.debug {
			log.Printf("Response: Sending %d bytes (encoded: %d bytes) for session %s path %s",
				len(readData), len(encoded), sessionID[:8], r.URL.Path)
		}
		w.Write([]byte(encoded))
	} else if s.debug {
		log.Printf("Response: No data to send for session %s path %s",
			sessionID[:8], r.URL.Path)
	}
}

func main() {
	var origin string
	var dest string
	var certFile string
	var keyFile string
	var debug bool
	var directMode bool
	var appCommand string
	var auth string

	flag.StringVar(&auth, "auth", "", "Basic auth (user:pass)")
    
    // 解析完参数后加上
    if auth != "" {
        parts := strings.Split(auth, ":")
        if len(parts) == 2 {
            server.username = parts[0] 
            server.password = parts[1]
        }
    }

	flag.StringVar(&origin, "o", "http://0.0.0.0:8080", "Origin address (e.g., http://0.0.0.0:8080)")
	flag.StringVar(&dest, "d", "", "Destination address (e.g., localhost:22)")
	flag.StringVar(&certFile, "c", "", "Path to certificate file")
	flag.StringVar(&keyFile, "k", "", "Path to private key file")
	flag.StringVar(&appCommand, "a", "", "Application command to run")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&directMode, "direct", false, "Enable direct connection mode")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		log.Fatalf("Invalid origin URL: %v", err)
	}

	if originURL.Scheme != "http" && originURL.Scheme != "https" {
		log.Fatal("Origin scheme must be either 'http' or 'https'")
	}

	originHost, originPort, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		log.Fatalf("Invalid origin address: %v", err)
	}

	var destHost, destPort string
	if dest != "" {
		destHost, destPort, err = net.SplitHostPort(dest)
		if err != nil {
			log.Fatalf("Invalid destination address: %v", err)
		}
	}

	server := NewServer(destHost, destPort, appCommand, debug, directMode)

	log.Printf("Server running on %s://%s:%s", originURL.Scheme, originHost, originPort)
	if directMode {
		log.Printf("Running in direct connection mode")
	}

	if originURL.Scheme == "https" {
		if certFile == "" || keyFile == "" {
			log.Fatal("HTTPS requires both certificate (-c) and key (-k) files")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load certificate and key: %v", err)
		}

		server := &http.Server{
			Addr:    fmt.Sprintf("%s:%s", originHost, originPort),
			Handler: http.HandlerFunc(server.handleRequest),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:  tls.VersionTLS12,
				MaxVersion:  tls.VersionTLS13,
				ClientAuth:  tls.NoClientCert,
				NextProtos: []string{"h2", "http/1.1"},
			},
		}

		log.Printf("Starting HTTPS server on %s:%s", originHost, originPort)
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	} else {
		server := &http.Server{
			Addr:    fmt.Sprintf("%s:%s", originHost, originPort),
			Handler: http.HandlerFunc(server.handleRequest),
		}
		log.Fatal(server.ListenAndServe())
	}
}
