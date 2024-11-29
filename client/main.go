package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	minLen  = 1
	maxLen  = 15
)

type Client struct {
	username    string  // 新增
    password    string  // 新增
	targetHost   string
	targetPort   int
	scheme      string
	sessionID   string
	httpClient  *http.Client
	debug       bool
	maxBodySize int64
	rateLimiter *rate.Limiter
	directMode  bool
}

func secureRandomInt(max int) int {
	var result int
	binary := make([]byte, 8)
	_, err := rand.Read(binary)
	if err != nil {
		return int(time.Now().UnixNano() % int64(max))
	}
	result = int(binary[0]) % max
	return result
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func NewClient(targetHost string, targetPort int, scheme string, debug bool, directMode bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
		ForceAttemptHTTP2:  !directMode,
	}


	return &Client{
        targetHost:   targetHost,
		targetPort:   targetPort,
		scheme:      scheme,
		username:    username,
        password:    password,
		sessionID:   generateSessionID(),
		httpClient:  &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		debug:       debug,
		maxBodySize: 10 * 1024 * 1024,
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 100),
		directMode:  directMode,
	}
}

func (c *Client) debugLog(format string, v ...interface{}) {
	if c.debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (c *Client) createRequest(method, path string, body io.Reader) (*http.Request, error) {
	var fullURL string
	if c.directMode {
		fullURL = fmt.Sprintf("%s://%s:%d/%s", c.scheme, c.targetHost, c.targetPort, path)
	} else {
		fullURL = fmt.Sprintf("%s://%s:%d/%s", c.scheme, c.targetHost, c.targetPort, randomFilename())
	}

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}

	// 添加Basic认证
    req.SetBasicAuth(c.username, c.password)  // 新增此行

	req.Header.Set("X-Session-ID", c.sessionID)
	req.Header.Set("Cache-Control", "no-cache")
	
	if !c.directMode {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("X-Ephemeral", c.sessionID)
	} else {
		req.Header.Set("User-Agent", "DarkFlare-Direct/1.0")
	}

	if c.debug {
		c.debugLog("Created %s request to: %s", method, fullURL)
	}

	return req, nil
}

func (c *Client) handleConnection(conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	if !c.rateLimiter.Allow() {
		c.debugLog("Rate limit exceeded")
		return
	}

	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()

	c.debugLog("New connection established - Local: %s, Remote: %s", localAddr, remoteAddr)

	done := make(chan struct{})
	var closeOnce sync.Once

	safeClose := func() {
		closeOnce.Do(func() {
			close(done)
			req, _ := c.createRequest(http.MethodPost, "close", nil)
			if req != nil {
				req = req.WithContext(ctx)
				resp, _ := c.httpClient.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
			}
			c.debugLog("Connection cleanup completed for %s", remoteAddr)
		})
	}

	defer safeClose()

	go func() {
		defer safeClose()
		buffer := make([]byte, 8192)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						c.debugLog("Error reading from local connection: %v", err)
					}
					return
				}

				if n > 0 {
					c.debugLog("Read %d bytes from local connection", n)
					req, err := c.createRequest(http.MethodPost, "data", bytes.NewReader(buffer[:n]))
					if err != nil {
						c.debugLog("Error creating POST request: %v", err)
						return
					}

					req = req.WithContext(ctx)
					req.Header.Set("Content-Type", "application/octet-stream")

					start := time.Now()
					resp, err := c.httpClient.Do(req)
					if err != nil {
						c.debugLog("Error making POST request: %v", err)
						return
					}
					c.debugLog("POST request completed in %v, status: %s", time.Since(start), resp.Status)
					resp.Body.Close()
				}
			}
		}
	}()

	go func() {
		defer safeClose()
		for {
			select {
			case <-ctx.Done():
				c.debugLog("Context cancelled, stopping polling for %s", remoteAddr)
				return
			case <-done:
				c.debugLog("Polling stopped for %s", remoteAddr)
				return
			default:
				req, err := c.createRequest(http.MethodGet, "data", nil)
				if err != nil {
					c.debugLog("Error creating GET request: %v", err)
					return
				}

				req = req.WithContext(ctx)
				resp, err := c.httpClient.Do(req)
				if err != nil {
					c.debugLog("Error making GET request: %v", err)
					time.Sleep(time.Second)
					continue
				}

				data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
				resp.Body.Close()

				if err != nil {
					c.debugLog("Error reading response body: %v", err)
					continue
				}

				if len(data) > 0 {
					if bytes.Contains(data, []byte("<!DOCTYPE html>")) || bytes.Contains(data, []byte("<html>")) {
						c.debugLog("Received HTML response instead of data - possible server error")
						time.Sleep(time.Second * 5)
						continue
					}

					decoded, err := hex.DecodeString(string(data))
					if err != nil {
						c.debugLog("Error decoding data: %v", err)
						continue
					}

					_, err = conn.Write(decoded)
					if err != nil {
						c.debugLog("Error writing to local connection: %v", err)
						return
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	select {
	case <-ctx.Done():
		c.debugLog("Context timeout reached for %s", remoteAddr)
	case <-done:
		c.debugLog("Connection handler completed for %s", remoteAddr)
	}
}

func randomString(min, max int) string {
	length := min + secureRandomInt(max-min+1)
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[secureRandomInt(len(charset))]
	}
	return string(b)
}

func randomFilename() string {
	extensions := []string{
		".html", ".htm", ".php", ".asp", ".jsp", ".js", ".css",
		".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
		".pdf", ".txt", ".doc", ".docx",
		".zip", ".rar", ".7z",
		".xml", ".json", ".csv",
	}
	return randomString(minLen, maxLen) + extensions[secureRandomInt(len(extensions))]
}

func main() {
	var localPort int
	var targetURL string
	var debug bool
	var directMode bool

	flag.IntVar(&localPort, "l", 0, "Local port to listen on")
	flag.StringVar(&targetURL, "t", "", "Target URL")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&directMode, "direct", false, "Enable direct connection mode")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	if localPort == 0 || targetURL == "" {
		fmt.Fprintf(os.Stderr, "Error: Both -l and -t parameters are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid target URL: %v", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		log.Fatal("Scheme must be either 'http' or 'https'")
	}

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

	log.Printf("Client listening on port %d", localPort)
	log.Printf("Connecting via %s://%s:%d", scheme, host, destPort)
	if directMode {
		log.Printf("Running in direct connection mode")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		   // 使用已经解析好的信息创建客户端
		   username := ""
		   password := ""
		   if u.User != nil {
			   username = u.User.Username()
			   password, _ = u.User.Password()
		   }
		   
		   host := u.Hostname()  // 这些变量在前面已经有了
		   client := NewClient(host, destPort, scheme, debug, directMode, username, password)

		//client := NewClient(host, destPort, scheme, debug, directMode)
	

		go client.handleConnection(conn)
	}
}
