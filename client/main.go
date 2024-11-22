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
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
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
	cloudflareHost string
	sessionID      string
	httpClient     *http.Client
	debug          bool
	maxBodySize    int64
	rateLimiter    *rate.Limiter
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(cryptorand.Reader, b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func NewClient(cloudflareHost string, debug bool) *Client {
	rand.Seed(time.Now().UnixNano())

	if !strings.HasPrefix(cloudflareHost, "https://") {
		cloudflareHost = "https://" + cloudflareHost
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}

	return &Client{
		cloudflareHost: cloudflareHost,
		sessionID:      generateSessionID(),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		debug:       debug,
		maxBodySize: 10 * 1024 * 1024,
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 100),
	}
}

func (c *Client) debugLog(format string, v ...interface{}) {
	if c.debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (c *Client) createDebugRequest(method, baseURL string, body io.Reader) (*http.Request, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + strings.TrimPrefix(baseURL, "https://")
	}

	fullURL := fmt.Sprintf("%s/%s", baseURL, randomFilename())
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

	// Modern Chrome headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", "\"Google Chrome\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("DNT", "1")

	c.debugLog("Making %s request to: %s (Host: %s)", method, fullURL, host)

	if c.debug {
		trace := &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				c.debugLog("Getting connection for %s", hostPort)
			},
			GotConn: func(info httptrace.GotConnInfo) {
				c.debugLog("Got connection: reused=%v, was_idle=%v, idle_time=%v, local=%v, remote=%v",
					info.Reused, info.WasIdle, info.IdleTime, info.Conn.LocalAddr(), info.Conn.RemoteAddr())
			},
			ConnectStart: func(network, addr string) {
				c.debugLog("Starting connection: network=%s, addr=%s", network, addr)
			},
			ConnectDone: func(network, addr string, err error) {
				if err != nil {
					c.debugLog("Connection failed: network=%s, addr=%s, err=%v", network, addr, err)
				} else {
					c.debugLog("Connection established: network=%s, addr=%s", network, addr)
				}
			},
			TLSHandshakeStart: func() {
				c.debugLog("Starting TLS handshake")
			},
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				if err != nil {
					c.debugLog("TLS handshake failed: %v", err)
				} else {
					c.debugLog("TLS handshake complete: version=%x, cipher=%x, resumed=%v",
						state.Version, state.CipherSuite, state.DidResume)
				}
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
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

	// Create channels for coordinating goroutine shutdown
	done := make(chan struct{})
	var closeOnce sync.Once

	// Safe close function
	safeClose := func() {
		closeOnce.Do(func() {
			close(done)
			// Send final POST to notify server of disconnection
			req, _ := c.createDebugRequest(http.MethodPost, c.cloudflareHost, nil)
			if req != nil {
				req = req.WithContext(ctx)
				req.Header.Set("X-Ephemeral", c.sessionID)
				req.Header.Set("User-Agent", "DarkFlare/1.0")
				req.Header.Set("X-Connection-Close", "true")
				resp, _ := c.httpClient.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
			}
			c.debugLog("Connection cleanup completed for %s", remoteAddr)
		})
	}

	defer safeClose()

	// Start the reader goroutine
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
					req, err := c.createDebugRequest(http.MethodPost, c.cloudflareHost, bytes.NewReader(buffer[:n]))
					if err != nil {
						c.debugLog("Error creating POST request: %v", err)
						return
					}

					req = req.WithContext(ctx)
					req.Header.Set("X-Ephemeral", c.sessionID)
					req.Header.Set("User-Agent", "DarkFlare/1.0")
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

	// Start the polling goroutine
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
				req, err := c.createDebugRequest(http.MethodGet, c.cloudflareHost, nil)
				if err != nil {
					c.debugLog("Error creating GET request: %v", err)
					return
				}

				req = req.WithContext(ctx)
				req.Header.Set("X-Ephemeral", c.sessionID)
				req.Header.Set("User-Agent", "DarkFlare/1.0")

				resp, err := c.httpClient.Do(req)
				if err != nil {
					c.debugLog("Error making GET request: %v", err)
					time.Sleep(time.Second)
					continue
				}

				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
					c.debugLog("Server returned non-200 status. Body: %s", string(body))
					resp.Body.Close()
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
					if bytes.HasPrefix(data, []byte("<")) {
						c.debugLog("Received HTML response instead of hex data")
						time.Sleep(time.Second)
						continue
					}

					decoded, err := hex.DecodeString(string(data))
					if err != nil {
						c.debugLog("Error decoding data: %v", err)
						time.Sleep(time.Second)
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

	// Wait for shutdown
	select {
	case <-ctx.Done():
		c.debugLog("Context timeout reached for %s", remoteAddr)
	case <-done:
		c.debugLog("Connection handler completed for %s", remoteAddr)
	}
}

func main() {
	var localPort int
	var cloudflareHost string
	var debug bool

	flag.IntVar(&localPort, "l", 0, "Local port to listen on")
	flag.StringVar(&cloudflareHost, "h", "", "Cloudflare hostname (e.g., foo.bar.net)")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	if localPort == 0 || cloudflareHost == "" {
		log.Fatal("Required parameters: -l <port> -h <cloudflare-hostname>")
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
	log.Printf("Connecting via https://%s", cloudflareHost)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		client := NewClient(cloudflareHost, debug)
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
