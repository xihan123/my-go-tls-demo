package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

const (
	defaultAddr          = ":443"
	shutdownTimeout      = 30 * time.Second
	readHeaderTimeout    = 10 * time.Second
	readTimeout          = 30 * time.Second
	writeTimeout         = 30 * time.Second
	idleTimeout          = 120 * time.Second
	maxHeaderBytes       = 1 << 20
	defaultSpeedTestSize = 100 << 20
	maxSpeedTestSize     = 1 << 30
	defaultMaxTraffic    = int64(3) << 40 // 3TB
)

func getRealIP(r *http.Request) string {
	singleIPHeaders := []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"Ali-Cdn-Real-IP",
		"Cdn-Real-IP",
		"Cdn-Src-IP",
		"X-Real-IP",
		"Client-IP",
		"X-Cluster-Client-IP",
		"WL-Proxy-Client-IP",
		"Proxy-Client-IP",
	}

	for _, h := range singleIPHeaders {
		if ip := strings.TrimSpace(r.Header.Get(h)); ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
	}

	for _, h := range []string{"X-Forwarded-For", "X-Forwarded", "Forwarded-For", "Forwarded"} {
		if val := r.Header.Get(h); val != "" {
			ips := strings.Split(val, ",")
			for i := len(ips) - 1; i >= 0; i-- {
				if ip := strings.TrimSpace(ips[i]); ip != "" && net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

type SpeedTestManager struct {
	downloadCnt  atomic.Int64
	totalBytes   atomic.Int64
	trafficQuota atomic.Int64 // remaining bytes, -1 = unlimited
	whitelist    []*net.IPNet
	allowAll     bool
	statsFile    string
	mu           sync.Mutex
}

func NewSpeedTestManager(whitelistStr, statsFile string, maxTraffic int64) *SpeedTestManager {
	m := &SpeedTestManager{statsFile: statsFile}
	m.parseWhitelist(whitelistStr)
	m.loadStats()
	if maxTraffic <= 0 {
		m.trafficQuota.Store(-1)
		log.Printf("Traffic quota: unlimited")
	} else {
		used := m.totalBytes.Load()
		remain := maxTraffic - used
		if remain < 0 {
			remain = 0
		}
		m.trafficQuota.Store(remain)
		log.Printf("Traffic quota: %.2f TB (used %.2f MB, limit %.2f TB)", float64(remain)/(1<<40), float64(used)/(1<<20), float64(maxTraffic)/(1<<40))
	}
	return m
}

func (m *SpeedTestManager) parseWhitelist(s string) {
	if s == "" || s == "*" {
		m.allowAll = true
		return
	}

	for _, cidr := range strings.Split(s, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("invalid whitelist entry: %s", cidr)
			continue
		}
		m.whitelist = append(m.whitelist, ipNet)
	}
}

func (m *SpeedTestManager) isAllowed(ipStr string) bool {
	if m.allowAll {
		return true
	}

	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, ipNet := range m.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *SpeedTestManager) recordDownload(bytes int64, countDownload bool) {
	if countDownload {
		m.downloadCnt.Add(1)
	}
	m.totalBytes.Add(bytes)
	m.saveStats()
}

func (m *SpeedTestManager) tryReserve(n int64) bool {
	for {
		remain := m.trafficQuota.Load()
		if remain < 0 {
			return true
		}
		if remain < n {
			log.Printf("Traffic quota exceeded: need %d, remain %d", n, remain)
			return false
		}
		if m.trafficQuota.CompareAndSwap(remain, remain-n) {
			log.Printf("Traffic reserved %d bytes, remain %d bytes", n, remain-n)
			return true
		}
	}
}

func (m *SpeedTestManager) getStats() (downloads, totalBytes int64, quotaRemain int64) {
	return m.downloadCnt.Load(), m.totalBytes.Load(), m.trafficQuota.Load()
}

type statsJSON struct {
	Downloads  int64 `json:"downloads"`
	TotalBytes int64 `json:"total_bytes"`
}

func (m *SpeedTestManager) loadStats() {
	if m.statsFile == "" {
		return
	}
	data, err := os.ReadFile(m.statsFile)
	if err != nil {
		return
	}
	var s statsJSON
	if err := json.Unmarshal(data, &s); err != nil {
		return
	}
	m.downloadCnt.Store(s.Downloads)
	m.totalBytes.Store(s.TotalBytes)
}

func (m *SpeedTestManager) saveStats() {
	if m.statsFile == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := json.Marshal(statsJSON{
		Downloads:  m.downloadCnt.Load(),
		TotalBytes: m.totalBytes.Load(),
	})
	if err != nil {
		return
	}
	dir := filepath.Dir(m.statsFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	_ = os.WriteFile(m.statsFile, data, 0644)
}

func parseSizeParam(s string) (int64, error) {
	if s == "" {
		return defaultSpeedTestSize, nil
	}

	s = strings.TrimSpace(strings.ToUpper(s))
	var mult int64 = 1

	switch {
	case strings.HasSuffix(s, "TB"):
		mult = 1 << 40
		s = strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size: %s", s)
	}
	return n * mult, nil
}

type Server struct {
	httpServer      *http.Server
	http3Server     *http3.Server
	httpPlainServer *http.Server
	tlsConfig       *tls.Config
	certPath        string
	keyPath         string
	shutdownMu      sync.Mutex
	shutdownCh      chan struct{}
	speedTestMgr    *SpeedTestManager
	behindProxy     bool
}

type Config struct {
	Addr           string
	HTTPAddr       string
	CertPath       string
	KeyPath        string
	SpeedWhitelist string
	StatsFile      string
	MaxTraffic     int64
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = defaultAddr
	}

	certPath, err := filepath.Abs(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("invalid cert path: %w", err)
	}
	keyPath, err := filepath.Abs(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("invalid key path: %w", err)
	}

	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	log.Printf("Using certificate: %s", certPath)

	behindProxy := cfg.HTTPAddr != ""
	s := &Server{
		certPath:     certPath,
		keyPath:      keyPath,
		shutdownCh:   make(chan struct{}),
		speedTestMgr: NewSpeedTestManager(cfg.SpeedWhitelist, cfg.StatsFile, cfg.MaxTraffic),
		behindProxy:  behindProxy,
	}

	handler := s.createHandler()

	tcpTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
		GetCertificate:   s.getCertificate,
	}

	quicTLS := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		GetCertificate:   s.getCertificate,
	}
	s.tlsConfig = http3.ConfigureTLSConfig(quicTLS)

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		TLSConfig:         tcpTLS,
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(os.Stderr, "HTTPS: ", log.LstdFlags),
	}

	s.http3Server = &http3.Server{
		Addr:       cfg.Addr,
		Handler:    handler,
		TLSConfig:  s.tlsConfig,
		QUICConfig: &quic.Config{MaxIdleTimeout: idleTimeout},
	}

	if cfg.HTTPAddr != "" {
		s.httpPlainServer = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           handler,
			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          log.New(os.Stderr, "HTTP: ", log.LstdFlags),
		}
		log.Printf("HTTP listener enabled on %s (Cloudflare Flexible mode)", cfg.HTTPAddr)
	}

	return s, nil
}

func (s *Server) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	return &cert, nil
}

func (s *Server) createHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/stats", s.statsHandler)
	mux.HandleFunc("/download", s.speedTestHandler)
	mux.HandleFunc("/generate_204", s.generate204Handler)
	mux.HandleFunc("/", s.defaultHandler)

	handler := s.securityMiddleware(mux)
	h2Handler, err := s.configureHTTP2(handler)
	if err != nil {
		log.Printf("HTTP/2 config error: %v", err)
		return handler
	}
	return h2Handler
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(filepath.Clean(r.URL.Path), "..") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		if !s.behindProxy {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if err := s.http3Server.SetQUICHeaders(w.Header()); err != nil {
			log.Printf("SetQUICHeaders: %v", err)
		}
		realIP := getRealIP(r)
		log.Printf("[%s] %s %s (via %s) %s", r.Method, r.URL.Path, realIP, r.RemoteAddr, r.Proto)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) configureHTTP2(handler http.Handler) (http.Handler, error) {
	h2s := &http2.Server{
		MaxConcurrentStreams:         250,
		MaxReadFrameSize:             1 << 20,
		IdleTimeout:                  idleTimeout,
		MaxUploadBufferPerConnection: 1 << 20,
		MaxUploadBufferPerStream:     256 << 10,
	}
	return h2c.NewHandler(handler, h2s), nil
}

func (s *Server) speedTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	realIP := getRealIP(r)
	if !s.speedTestMgr.isAllowed(realIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sizeStr := r.URL.Query().Get("size")
	size, err := parseSizeParam(sizeStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if size > maxSpeedTestSize {
		http.Error(w, fmt.Sprintf("max size is %dGB", maxSpeedTestSize>>30), http.StatusBadRequest)
		return
	}

	if !s.speedTestMgr.tryReserve(size) {
		http.Error(w, "Traffic quota exceeded", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=test%dMB.bin", size>>20))

	sw := &statsWriter{ResponseWriter: w}
	http.ServeContent(sw, r, "test.bin", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), &virtualReader{size: size})
	isRange := r.Header.Get("Range") != ""
	s.speedTestMgr.recordDownload(sw.n, !isRange)
}

var patternBlock [64 << 10]byte

func init() {
	for i := range patternBlock {
		patternBlock[i] = byte(i ^ (i >> 8) ^ (i >> 16))
	}
}

type virtualReader struct {
	size   int64
	offset int64
}

func (v *virtualReader) Read(p []byte) (int, error) {
	if v.offset >= v.size {
		return 0, io.EOF
	}

	remain := v.size - v.offset
	n := int64(len(p))
	if n > remain {
		n = remain
	}

	var written int64
	for written < n {
		off := (v.offset + written) % int64(len(patternBlock))
		chunk := n - written
		if chunk > int64(len(patternBlock))-off {
			chunk = int64(len(patternBlock)) - off
		}
		copy(p[written:written+chunk], patternBlock[off:])
		written += chunk
	}

	v.offset += n
	return int(n), nil
}

func (v *virtualReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		v.offset = offset
	case io.SeekCurrent:
		v.offset += offset
	case io.SeekEnd:
		v.offset = v.size + offset
	}
	if v.offset < 0 {
		v.offset = 0
	}
	if v.offset > v.size {
		v.offset = v.size
	}
	return v.offset, nil
}

type statsWriter struct {
	http.ResponseWriter
	n int64
}

func (w *statsWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *statsWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statsWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	downloads, total, remain := s.speedTestMgr.getStats()
	w.Header().Set("Content-Type", "application/json")
	quotaStr := "unlimited"
	if remain >= 0 {
		quotaStr = fmt.Sprintf(`"%.2f"`, float64(remain)/(1<<40))
	}
	_, err := fmt.Fprintf(w, `{"downloads":%d,"total_bytes":%d,"total_mb":%.2f,"traffic_remaining_tb":%s}`, downloads, total, float64(total)/(1<<20), quotaStr)
	if err != nil {
		return
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	select {
	case <-s.shutdownCh:
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, `{"status":"shutting_down"}`)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"healthy"}`)
	}
}

func (s *Server) generate204Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var tlsVersion, tlsCipher string
	if tlsState := r.TLS; tlsState != nil {
		tlsVersion = tlsVersionName(tlsState.Version)
		tlsCipher = tlsCipherSuiteName(tlsState.CipherSuite)
	} else {
		tlsVersion = "-"
		tlsCipher = "-"
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	proto := r.Proto
	if r.ProtoMajor == 3 {
		proto = "HTTP/3"
	}

	realIP := getRealIP(r)
	_, used, remain := s.speedTestMgr.getStats()

	html := `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HTTPS Server</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font:14px/1.5 system-ui,sans-serif;background:#0a0a0a;color:#ccc;min-height:100vh;padding:24px 16px}
.wrap{max-width:520px;margin:0 auto}
h1{font-size:1.25em;color:#fff;margin-bottom:4px;font-weight:600}
.tag{font-size:12px;color:#555;margin-bottom:20px}
.card{background:#181818;border-radius:8px;padding:16px;margin-bottom:12px}
.card h2{font-size:11px;color:#666;margin-bottom:12px;font-weight:500}
.row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #252525}
.row:last-child{border:none}
.key{color:#666}
.val{color:#ddd;text-align:right;word-break:break-all;max-width:65%}
a{color:#5af;text-decoration:none}
a:hover{text-decoration:underline}
code{background:#252525;padding:2px 6px;border-radius:4px;font-size:13px;color:#5af}
</style>
</head>
<body>
<div class="wrap">
<h1>HTTPS Server</h1>
<p class="tag">` + Version + `</p>

<div class="card">
<h2>Connection</h2>
<div class="row"><span class="key">Protocol</span><span class="val">` + proto + `</span></div>
<div class="row"><span class="key">TLS</span><span class="val">` + tlsVersion + `</span></div>
<div class="row"><span class="key">Cipher</span><span class="val">` + tlsCipher + `</span></div>
<div class="row"><span class="key">Host</span><span class="val">` + hostname + `</span></div>
<div class="row"><span class="key">IP</span><span class="val">` + realIP + `</span></div>
<div class="row"><span class="key">Time</span><span class="val">` + time.Now().Format("2006-01-02 15:04:05") + `</span></div>
</div>

<div class="card">
<h2>Stats</h2>
` + formatQuota(used, remain) + `
</div>

<div class="card">
<h2>Endpoints</h2>
<div class="row"><code><a href="/health">/health</a></code><span class="val">health check</span></div>
<div class="row"><code><a href="/stats">/stats</a></code><span class="val">statistics</span></div>
<div class="row"><code><a href="/download">/download</a></code><span class="val">speed test</span></div>
<div class="row"><code>/generate_204</code><span class="val">captive portal</span></div>
</div>

<div class="card">
<h2>Request</h2>
<div class="row"><span class="key">User-Agent</span><span class="val">` + r.UserAgent() + `</span></div>
</div>
</div>
</body>
</html>`
	_, _ = fmt.Fprint(w, html)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func tlsCipherSuiteName(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES-128-GCM-SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES-256-GCM-SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "CHACHA20-POLY1305-SHA256"
	default:
		return fmt.Sprintf("0x%x", cipherSuite)
	}
}

func formatQuota(used, remain int64) string {
	if remain < 0 {
		usedStr := formatBytes(used)
		return `<div class="row"><span class="key">Used</span><span class="val">` + usedStr + `</span></div>
<div class="row"><span class="key">Quota</span><span class="val">Unlimited</span></div>`
	}
	return `<div class="row"><span class="key">Used</span><span class="val">` + formatBytes(used) + `</span></div>
<div class="row"><span class="key">Quota</span><span class="val">` + formatBytes(remain) + `</span></div>`
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(1<<20))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tlsListener := tls.NewListener(listener, s.httpServer.TLSConfig)

	log.Printf("HTTPS server on %s (HTTP/2 + HTTP/3)", s.httpServer.Addr)

	errCh := make(chan error, 3)

	go func() {
		if err := s.httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http2: %w", err)
		}
	}()

	go func() {
		if err := s.http3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http3: %w", err)
		}
	}()

	if s.httpPlainServer != nil {
		go func() {
			log.Printf("HTTP server on %s (Cloudflare Flexible mode)", s.httpPlainServer.Addr)
			if err := s.httpPlainServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		_ = s.Shutdown()
		return err
	case <-s.shutdownCh:
		return s.Shutdown()
	case sig := <-signalChan():
		log.Printf("Signal: %v", sig)
		return s.Shutdown()
	}
}

func (s *Server) Shutdown() error {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	log.Println("Shutting down...")
	s.speedTestMgr.saveStats()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var errs []error
	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http2: %w", err))
	}
	if err := s.http3Server.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http3: %w", err))
	}
	if s.httpPlainServer != nil {
		if err := s.httpPlainServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("http: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func signalChan() <-chan os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return sigCh
}

func main() {
	var showVersion bool
	var whitelist string

	flag.BoolVar(&showVersion, "version", false, "show version info")
	flag.BoolVar(&showVersion, "v", false, "show version info (shorthand)")
	flag.StringVar(&whitelist, "whitelist", "", "speed test IP whitelist (comma-separated, overrides SPEED_WHITELIST)")
	flag.StringVar(&whitelist, "w", "", "speed test IP whitelist (shorthand)")
	flag.Parse()

	if showVersion {
		fmt.Printf("my-go-tls-demo %s\n", Version)
		fmt.Printf("Git commit: %s\n", GitCommit)
		fmt.Printf("Build date: %s\n", BuildDate)
		os.Exit(0)
	}

	_ = godotenv.Load()

	speedWhitelist := getEnvWithDefault("SPEED_WHITELIST", "*")
	if whitelist != "" {
		speedWhitelist = whitelist
	}

	maxTraffic := defaultMaxTraffic
	if v := os.Getenv("MAX_TRAFFIC"); v != "" {
		if t, err := parseSizeParam(v); err == nil {
			maxTraffic = t
		} else {
			log.Printf("invalid MAX_TRAFFIC: %v, using default 3TB", err)
		}
	}

	cfg := Config{
		Addr:           getEnvWithDefault("SERVER_ADDR", defaultAddr),
		HTTPAddr:       getEnvWithDefault("HTTP_ADDR", ""),
		CertPath:       getEnvWithDefault("CERT_PATH", "./certs/server.crt"),
		KeyPath:        getEnvWithDefault("KEY_PATH", "./certs/server.key"),
		SpeedWhitelist: speedWhitelist,
		StatsFile:      getEnvWithDefault("STATS_FILE", "./data/stats.json"),
		MaxTraffic:     maxTraffic,
	}

	server, err := NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
