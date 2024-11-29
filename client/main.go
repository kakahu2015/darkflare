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
	"math/rand"
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

type Client struct {
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

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func NewClient(targetHost string, targetPort int, scheme string, debug bool, directMode bool) *Client {
	rand.Seed(time.Now().UnixNano())

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
		sessionID:   generateSessionID(),
		httpClient:  &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		debug:       debug,
		maxBodySize: 10 * 1024 * 1024,
