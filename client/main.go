package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/x509"

	"golang.org/x/time/rate"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	minLen  = 1
	maxLen  = 15
)

type Client struct {
	cloudflareHost  string
	destPort        int
	destAddr        string
	scheme          string
	sessionID       string
	httpClient      *http.Client
	debug           bool
	maxBodySize     int64
	rateLimiter     *rate.Limiter
	bufferPool      sync.Pool
	sessions        sync.Map
	readBufferSize  int
	writeBufferSize int
	pollInterval    time.Duration
	batchSize       int
	authHeader      string    // 存储 Basic Auth header
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(cryptorand.Reader, b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func NewClient(cloudflareHost string, destPort int, scheme string, destAddr string, debug bool) *Client {
	rand.Seed(time.Now().UnixNano())

	if scheme == "" {
		scheme = "https"
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}

	// 在这里添加认证信息解析，在删除 http(s):// 前缀之前
	var authHeader string
	if u, err := url.Parse("//" + cloudflareHost); err == nil && u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		authHeader = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(username + ":" + password))
		// 从 host 中移除认证信息
		cloudflareHost = u.Host
	}

	cloudflareHost = strings.TrimPrefix(cloudflareHost, "http://")
	cloudflareHost = strings.TrimPrefix(cloudflareHost, "https://")

	client := &Client{
		cloudflareHost:  cloudflareHost,
		destPort:        destPort,
		destAddr:        destAddr,
		scheme:          scheme,
		sessionID:       generateSessionID(),
		debug:           debug,
		maxBodySize:     10 * 1024 * 1024,
		rateLimiter:     rate.NewLimiter(rate.Every(time.Millisecond*100), 1000),
		readBufferSize:  32 * 1024,
		writeBufferSize: 32 * 1024,
		pollInterval:    50 * time.Millisecond,
		batchSize:       32 * 1024,
		authHeader:      authHeader,  // 添加认证字段
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 64*1024) // Increase to 64KB
			},
		},
	}

	// Load system root CAs
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Warning: failed to load system cert pool: %v", err)
		rootCAs = x509.NewCertPool()
		if rootCAs == nil {
			log.Fatal("Failed to create cert pool")
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
			SessionTicketsDisabled:   false,
			InsecureSkipVerify:       true,
			NextProtos:               []string{"http/1.1"},
		},
		MaxIdleConns:          1,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   1,
		MaxConnsPerHost:       1,
		WriteBufferSize:       32 * 1024,
		ReadBufferSize:        32 * 1024,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client
}

func (c *Client) debugLog(format string, v ...interface{}) {
	if c.debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (c *Client) createDebugRequest(method, baseURL string, body io.Reader, closeConnection bool) (*http.Request, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	baseURL = strings.TrimPrefix(baseURL, "http://")
	baseURL = strings.TrimPrefix(baseURL, "https://")

	var fullURL string
	if (c.scheme == "https" && c.destPort == 443) || (c.scheme == "http" && c.destPort == 80) {
		fullURL = fmt.Sprintf("%s://%s/%s", c.scheme, baseURL, randomFilename())
	} else {
		fullURL = fmt.Sprintf("%s://%s:%d/%s", c.scheme, baseURL, c.destPort, randomFilename())
	}

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}

	host := strings.TrimPrefix(c.cloudflareHost, "https://")
	host = strings.TrimPrefix(host, "http://")
	req.Host = host

	// Cache control
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")

	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	// Modern Chrome headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("DNT", "1")

	// Base64 encode the destination (using the -d parameter)
	destString := c.destAddr
	encodedDest := base64.StdEncoding.EncodeToString([]byte(destString))

	// Add the encoded destination to headers
	req.Header.Set("X-Requested-With", encodedDest)
	req.Header.Set("X-For", c.sessionID)

	// Conditionally add the X-Connection-Close header
	if closeConnection {
		req.Header.Set("X-Connection-Close", "true")
	}

	// Debug logging for headers
	if c.debug {
		c.debugLog("Request Headers for %s:", fullURL)
		for k, v := range req.Header {
			c.debugLog("  %s: %s", k, v)
		}
	}

	return req, nil
}

func (c *Client) handleConnection(conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	defer conn.Close()

	// Use the existing sessionID instead of generating a new one
	sessionID := c.sessionID

	// Get a buffer from the pool
	buffer := c.bufferPool.Get().([]byte)
	defer c.bufferPool.Put(buffer)

	// Store session info with minimal synchronization
	sessionInfo := &struct {
		conn       net.Conn
		lastActive time.Time
		done       chan struct{}
		closeOnce  sync.Once
	}{
		conn:       conn,
		lastActive: time.Now(),
		done:       make(chan struct{}),
	}

	// Safe close function
	safeClose := func() {
		sessionInfo.closeOnce.Do(func() {
			close(sessionInfo.done)
		})
	}

	c.sessions.Store(sessionID, sessionInfo)
	defer c.sessions.Delete(sessionID)
	defer safeClose()

	// Start the polling goroutine
	go func() {
		ticker := time.NewTicker(c.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sessionInfo.done:
				return
			case <-ticker.C:
				if err := c.pollData(ctx, sessionID, conn); err != nil {
					if !strings.Contains(err.Error(), "EOF") {
						c.debugLog("Poll error for connection %s: %v", sessionID, err)
					}
					safeClose()
					return
				}
			}
		}
	}()

	// Main read loop - directly handle data without channels
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				c.debugLog("Read error for connection %s: %v", sessionID, err)
			}
			safeClose()
			break
		}
		if n > 0 {
			data := make([]byte, n)
			copy(data, buffer[:n])
			if err := c.sendData(ctx, sessionID, data, false); err != nil {
				c.debugLog("Send error for connection %s: %v", sessionID, err)
				safeClose()
				break
			}
		}
	}

	// Send connection termination notification
	req, err := c.createDebugRequest(http.MethodPost, c.cloudflareHost, nil, true)
	if err == nil {
		req = req.WithContext(context.Background())
		req.Header.Set("X-For", sessionID)
		req.Header.Set("X-Connection-Close", "true")
		resp, err := c.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}

func (c *Client) sendData(ctx context.Context, sessionID string, data []byte, closeConnection bool) error {
	if c.debug {
		c.debugLog("Sending data for session %s: %d bytes, closeConnection: %v", sessionID[:8], len(data), closeConnection)
	}

	req, err := c.createDebugRequest(http.MethodPost, c.cloudflareHost, bytes.NewReader(data), closeConnection)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("X-For", sessionID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if c.debug {
		c.debugLog("Received response for session %s: %d", sessionID[:8], resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) handleResponse(resp *http.Response, body []byte) {
	if resp.StatusCode != http.StatusOK {
		// Format error message
		errorMsg := fmt.Sprintf("\n╭─ CDN Error ─────────────────────────────────────────────────\n")
		errorMsg += fmt.Sprintf("│ Status: %d (%s)\n", resp.StatusCode, resp.Status)

		// Add common CDN error explanations
		switch resp.StatusCode {
		case http.StatusBadGateway:
			errorMsg += "│ Cause:  Origin server (darkflare-server) is unreachable\n"
		case http.StatusForbidden:
			errorMsg += "│ Cause:  Request blocked by CDN security rules\n"
		case http.StatusServiceUnavailable:
			errorMsg += "│ Cause:  CDN temporary error or rate limiting\n"
		case http.StatusGatewayTimeout:
			errorMsg += "│ Cause:  Origin server (darkflare-server) timed out\n"
		case http.StatusNotFound:
			errorMsg += "│ Cause:  Origin server not responding or incorrect path\n"
		}

		// If we got HTML content, parse it for specific errors
		if bytes.Contains(body, []byte("<!DOCTYPE html>")) || bytes.Contains(body, []byte("<html>")) {
			switch {
			case bytes.Contains(body, []byte("Index of /")):
				errorMsg += "│ Detail: Origin server returned directory listing\n"
				errorMsg += "│        Server is misconfigured or not running darkflare\n"
			case bytes.Contains(body, []byte("Error 521")):
				errorMsg += "│ Detail: Origin server is down (Cloudflare Error 521)\n"
			case bytes.Contains(body, []byte("Error 522")):
				errorMsg += "│ Detail: Connection timed out (Cloudflare Error 522)\n"
			case bytes.Contains(body, []byte("Error 523")):
				errorMsg += "│ Detail: Origin unreachable (Cloudflare Error 523)\n"
			case bytes.Contains(body, []byte("Error 524")):
				errorMsg += "│ Detail: Origin timeout (Cloudflare Error 524)\n"
			default:
				errorMsg += "│ Detail: Received HTML instead of tunnel data\n"
				errorMsg += "│        Server may be down or misconfigured\n"
			}
		} else if len(body) > 0 {
			// If we got binary data, just indicate it
			errorMsg += "│ Detail: Received unexpected binary response\n"
		}

		errorMsg += "──────────────────────────────────────────────────────────────\n"
		c.debugLog(errorMsg)
		return
	}
	// ... handle successful response ...
}

func (c *Client) pollData(ctx context.Context, sessionID string, conn net.Conn) error {
	req, err := c.createDebugRequest(http.MethodGet, c.cloudflareHost, nil, false)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("X-For", sessionID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
		c.handleResponse(resp, body)
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
	if err != nil {
		return err
	}

	if len(data) > 0 {
		// Check for HTML responses that indicate errors
		if bytes.Contains(data, []byte("<!DOCTYPE html>")) || bytes.Contains(data, []byte("<html>")) {
			switch {
			case bytes.Contains(data, []byte("Index of /")):
				return fmt.Errorf("server returned directory listing")
			case bytes.Contains(data, []byte("Error 521")):
				return fmt.Errorf("origin server is down (Cloudflare Error 521)")
			case bytes.Contains(data, []byte("Error 522")):
				return fmt.Errorf("connection timed out (Cloudflare Error 522)")
			case bytes.Contains(data, []byte("Error 523")):
				return fmt.Errorf("origin unreachable (Cloudflare Error 523)")
			case bytes.Contains(data, []byte("Error 524")):
				return fmt.Errorf("origin timeout (Cloudflare Error 524)")
			default:
				return fmt.Errorf("received HTML response instead of tunnel data")
			}
		}

		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			return fmt.Errorf("error decoding data: %v", err)
		}

		_, err = conn.Write(decoded)
		if err != nil {
			return fmt.Errorf("error writing to connection: %v", err)
		}
	}

	return nil
}

func main() {
	var localPort int
	var targetURL string
	var destAddr string
	var debug bool

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DarkFlare Client - TCP-over-CDN tunnel client component\n")
		fmt.Fprintf(os.Stderr, "(c) 2024 Barrett Lyon\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -l        Local port to listen on for incoming connections\n")
		fmt.Fprintf(os.Stderr, "            This is where your applications will connect to\n\n")
		fmt.Fprintf(os.Stderr, "  -t        Target URL of your cdn-protected darkflare-server\n")
		fmt.Fprintf(os.Stderr, "            Format: [http(s)://]hostname[:port]\n")
		fmt.Fprintf(os.Stderr, "            Default scheme: https, Default ports: 80/443\n")
		fmt.Fprintf(os.Stderr, "            This server will receive and forward your traffic\n\n")
		fmt.Fprintf(os.Stderr, "  -d        Destination address for the final connection\n")
		fmt.Fprintf(os.Stderr, "            Format: hostname:port\n")
		fmt.Fprintf(os.Stderr, "            This is where your traffic will ultimately be sent\n\n")
		fmt.Fprintf(os.Stderr, "  -debug    Enable detailed debug logging\n")
		fmt.Fprintf(os.Stderr, "            Shows connection details, data transfer, and errors\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  Basic SSH tunnel:\n")
		fmt.Fprintf(os.Stderr, "    %s -l 2222 -t https://cdn.miami.us.doxx.net -d ssh.destination.com:22\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Custom port with debugging:\n")
		fmt.Fprintf(os.Stderr, "    %s -l 8080 -t https://tunnel.example.com:8443 -d internal.service:80 -debug\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  HTTP proxy tunnel:\n")
		fmt.Fprintf(os.Stderr, "    %s -l 8080 -t http://proxy.example.com -d target.site.com:80\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage with SSH:\n")
		fmt.Fprintf(os.Stderr, "  1. Start the client: %s -l 2222 -t tunnel.example.com -d ssh.target.com:22\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  2. Connect via: ssh -p 2222 user@localhost\n\n")
		fmt.Fprintf(os.Stderr, "For more information: https://github.com/blyon/darkflare\n")
	}

	flag.IntVar(&localPort, "l", 0, "")
	flag.StringVar(&targetURL, "t", "", "")
	flag.StringVar(&destAddr, "d", "", "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	if localPort == 0 || targetURL == "" || destAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: -l, -t, and -d parameters are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Parse the target URL
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid target URL: %v", err)
	}

	// Extract scheme
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		log.Fatal("Scheme must be either 'http' or 'https'")
	}

	// Extract host and port
	host := u.Hostname()
	port := u.Port()
	destPort := 443
	if port != "" {
		destPort, err = strconv.Atoi(port)
		if err != nil {
			log.Fatalf("Invalid port number: %v", err)
		}
	} else if scheme == "http" {
		destPort = 80
	}

	if debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
		log.Printf("Debug mode enabled")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("DarkFlare client listening on port %d", localPort)
	log.Printf("Connecting via %s://%s:%d", scheme, host, destPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		client := NewClient(host, destPort, scheme, destAddr, debug)
		go client.handleConnection(conn)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func randomString(min, max int) string {
	if min < 0 || max < min {
		min, max = 1, 15
	}
	length := min + rand.Intn(max-min+1)
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomFilename() string {
	extensions := []string{
		// Common web files
		".html", ".htm", ".php", ".asp", ".jsp", ".js", ".css",
		// Images
		".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
		// Documents
		".pdf", ".txt", ".doc", ".docx",
		// Media
		".mp3", ".mp4", ".wav", ".avi",
		// Archives
		".zip", ".rar", ".7z",
		// Data
		".xml", ".json", ".csv",
		// Web fonts
		".woff", ".woff2", ".ttf", ".eot",
		// Config files
		".conf", ".cfg", ".ini",
	}
	return randomString(minLen, maxLen) + extensions[rand.Intn(len(extensions))]
}

func (c *Client) isDirectMode() bool {
	// If the host is an IP address or localhost, we're in direct mode
	host := strings.Split(c.cloudflareHost, ":")[0]
	ip := net.ParseIP(host)
	return ip != nil || host == "localhost" || host == "127.0.0.1" || host == "::1"
}
