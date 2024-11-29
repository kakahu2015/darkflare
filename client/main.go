package main

import (
    "bytes"
    "context"
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
)

type Client struct {
    targetHost    string
    localPort     int
    sessionID     string
    httpClient    *http.Client
    debug         bool
    maxBodySize   int64
}

func NewClient(targetHost string, localPort int, debug bool) *Client {
    // 生成随机会话ID
    sessionID := fmt.Sprintf("%x", rand.Int63())
    
    transport := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        MaxIdleConns:          100,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        DisableCompression:    true,
    }

    return &Client{
        targetHost:  targetHost,
        localPort:   localPort,
        sessionID:   sessionID,
        httpClient:  &http.Client{
            Transport: transport,
            Timeout:   30 * time.Second,
        },
        debug:       debug,
        maxBodySize: 10 * 1024 * 1024,
    }
}

func (c *Client) debugLog(format string, v ...interface{}) {
    if c.debug {
        log.Printf("[DEBUG] "+format, v...)
    }
}

func (c *Client) createRequest(method string, data io.Reader) (*http.Request, error) {
    // 构建URL，添加随机路径
    path := fmt.Sprintf("/%s", randomPath())
    req, err := http.NewRequest(method, fmt.Sprintf("%s%s", c.targetHost, path), data)
    if err != nil {
        return nil, err
    }

    // 添加常见的HTTP头，模拟浏览器请求
    req.Header.Set("User-Agent", randomUserAgent())
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")
    req.Header.Set("Accept-Encoding", "gzip, deflate")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("X-Ephemeral", c.sessionID)
    
    // 添加一些随机的合理头部
    if rand.Float64() < 0.3 {
        req.Header.Set("Cache-Control", "max-age=0")
    }
    if rand.Float64() < 0.5 {
        req.Header.Set("Upgrade-Insecure-Requests", "1")
    }
    if rand.Float64() < 0.3 {
        req.Header.Set("DNT", "1")
    }

    return req, nil
}

func (c *Client) handleConnection(conn net.Conn) {
    defer conn.Close()
    
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    var wg sync.WaitGroup
    
    // 读取本地连接数据并通过POST发送
    wg.Add(1)
    go func() {
        defer wg.Done()
        buffer := make([]byte, 8192)
        
        for {
            select {
            case <-ctx.Done():
                return
            default:
                n, err := conn.Read(buffer)
                if err != nil {
                    if err != io.EOF {
                        c.debugLog("Local read error: %v", err)
                    }
                    cancel()
                    return
                }

                if n > 0 {
                    req, err := c.createRequest(http.MethodPost, bytes.NewReader(buffer[:n]))
                    if err != nil {
                        c.debugLog("Create POST request error: %v", err)
                        continue
                    }

                    resp, err := c.httpClient.Do(req)
                    if err != nil {
                        c.debugLog("POST request error: %v", err)
                        continue
                    }
                    resp.Body.Close()
                }
            }
        }
    }()

    // 通过GET请求获取数据并写入本地连接
    wg.Add(1)
    go func() {
        defer wg.Done()
        ticker := time.NewTicker(50 * time.Millisecond)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                req, err := c.createRequest(http.MethodGet, nil)
                if err != nil {
                    c.debugLog("Create GET request error: %v", err)
                    continue
                }

                resp, err := c.httpClient.Do(req)
                if err != nil {
                    c.debugLog("GET request error: %v", err)
                    time.Sleep(time.Second)
                    continue
                }

                if resp.StatusCode == http.StatusOK {
                    data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
                    resp.Body.Close()
                    
                    if err != nil {
                        c.debugLog("Read response error: %v", err)
                        continue
                    }

                    if len(data) > 0 {
                        decoded, err := hex.DecodeString(string(data))
                        if err != nil {
                            c.debugLog("Decode data error: %v", err)
                            continue
                        }

                        _, err = conn.Write(decoded)
                        if err != nil {
                            c.debugLog("Local write error: %v", err)
                            cancel()
                            return
                        }
                    }
                } else {
                    resp.Body.Close()
                    time.Sleep(time.Second)
                }
            }
        }
    }()

    wg.Wait()
}

func main() {
    var localPort int
    var targetURL string
    var debug bool

    flag.IntVar(&localPort, "l", 0, "Local port to listen on")
    flag.StringVar(&targetURL, "t", "", "Target URL (e.g., https://example.com)")
    flag.BoolVar(&debug, "debug", false, "Enable debug logging")
    flag.Parse()

    if localPort == 0 || targetURL == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -l <local_port> -t <target_url> [-debug]\n", os.Args[0])
        os.Exit(1)
    }

    if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
        targetURL = "https://" + targetURL
    }

    // 验证URL
    _, err := url.Parse(targetURL)
    if err != nil {
        log.Fatalf("Invalid target URL: %v", err)
    }

    if debug {
        log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
    }

    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Listening on :%d, target: %s", localPort, targetURL)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }

        client := NewClient(targetURL, localPort, debug)
        go client.handleConnection(conn)
    }
}

// 辅助函数

func randomPath() string {
    paths := []string{
        "assets", "static", "img", "css", "js", "media",
        "docs", "files", "content", "resources", "data",
    }
    
    extensions := []string{
        ".jpg", ".png", ".gif", ".css", ".js", ".html",
        ".php", ".asp", ".txt", ".xml", ".json",
    }
    
    path := paths[rand.Intn(len(paths))]
    filename := randomString(5, 10) + extensions[rand.Intn(len(extensions))]
    
    // 有时添加子目录
    if rand.Float64() < 0.3 {
        path += "/" + randomString(3, 8)
    }
    
    return path + "/" + filename
}

func randomString(minLen, maxLen int) string {
    charset := "abcdefghijklmnopqrstuvwxyz0123456789"
    length := minLen + rand.Intn(maxLen-minLen+1)
    result := make([]byte, length)
    for i := range result {
        result[i] = charset[rand.Intn(len(charset))]
    }
    return string(result)
}

func randomUserAgent() string {
    agents := []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    }
    return agents[rand.Intn(len(agents))]
}
