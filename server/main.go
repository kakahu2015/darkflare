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
}

func NewServer(destHost, destPort string, appCommand string, debug bool) *Server {
    s := &Server{
        destHost:    destHost,
        destPort:    destPort,
        debug:       debug,
        appCommand:  appCommand,
        isAppMode:   appCommand != "",
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
        log.Printf("Handling application request from %s", r.RemoteAddr)
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
    if s.isAppMode {
        s.handleApplication(w, r)
        return
    }

    if s.debug {
        log.Printf("Request: %s %s from %s",
            r.Method,
            r.URL.Path,
            r.RemoteAddr,
        )
        log.Printf("Headers: %+v", r.Header)
    }

    // Set Apache-like headers for better disguise
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

    // Get session ID from header
    sessionID := r.Header.Get("X-Ephemeral")
    if sessionID == "" {
        sessionID = r.RemoteAddr // 使用客户端IP作为会话ID
    }

    if sessionID == "" {
        if s.debug {
            log.Printf("Error: Missing session ID from %s", r.RemoteAddr)
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
                    sessionID,
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

    // For GET requests, read available data
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
                    sessionID,
                )
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
            log.Printf("Response: Sending %d bytes (encoded: %d bytes) for session %s",
                len(readData),
                len(encoded),
                sessionID,
            )
        }
        w.Write([]byte(encoded))
    }
}

func main() {
    var listenAddr string
    var dest string
    var debug bool
    var appCommand string

    flag.StringVar(&listenAddr, "l", "localhost:8080", "Listen address")
    flag.StringVar(&dest, "d", "", "Destination address (host:port)")
    flag.StringVar(&appCommand, "a", "", "Application command")
    flag.BoolVar(&debug, "debug", false, "Enable debug logging")
    flag.Parse()

    if dest == "" && appCommand == "" {
        log.Fatal("Either destination (-d) or application command (-a) is required")
    }

    var destHost, destPort string
    if dest != "" {
        var err error
        destHost, destPort, err = net.SplitHostPort(dest)
        if err != nil {
            log.Fatalf("Invalid destination address: %v", err)
        }
    }

    server := NewServer(destHost, destPort, appCommand, debug)

    listenHost, listenPort, err := net.SplitHostPort(listenAddr)
    if err != nil {
        log.Fatalf("Invalid listen address: %v", err)
    }

    log.Printf("DarkFlare server running on http://%s:%s", listenHost, listenPort)

    http.HandleFunc("/", server.handleRequest)
    log.Fatal(http.ListenAndServe(listenAddr, nil))
}
