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
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

type Client struct {
	cloudflareHost string
	sessionID      string
	httpClient     *http.Client
	debug          bool
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func NewClient(cloudflareHost string, debug bool) *Client {
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
		debug: debug,
	}
}

func (c *Client) debugLog(format string, v ...interface{}) {
	if c.debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (c *Client) createDebugRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

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
	}()

	// Start the polling goroutine
	go func() {
		defer safeClose()
		for {
			select {
			case <-done:
				c.debugLog("Polling stopped for %s", remoteAddr)
				return
			default:
				req, err := c.createDebugRequest(http.MethodGet, c.cloudflareHost, nil)
				if err != nil {
					c.debugLog("Error creating GET request: %v", err)
					return
				}

				req.Header.Set("X-Ephemeral", c.sessionID)
				req.Header.Set("User-Agent", "DarkFlare/1.0")

				resp, err := c.httpClient.Do(req)
				if err != nil {
					c.debugLog("Error making GET request: %v", err)
					time.Sleep(time.Second)
					continue
				}

				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					c.debugLog("Server returned non-200 status. Body: %s", string(body))
					resp.Body.Close()
					time.Sleep(time.Second)
					continue
				}

				data, err := io.ReadAll(resp.Body)
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
	<-done
	c.debugLog("Connection handler completed for %s", remoteAddr)
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
