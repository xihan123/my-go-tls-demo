package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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
	defaultAddr = ":443"

	shutdownTimeout = 30 * time.Second

	readHeaderTimeout = 10 * time.Second

	readTimeout = 30 * time.Second

	writeTimeout = 30 * time.Second

	idleTimeout = 120 * time.Second

	maxHeaderBytes = 1 << 20

	certOrganization = "Self-Signed Certificate"

	certValidYears = 10

	rsaKeyBits = 4096

	defaultSpeedTestSize = 100 << 20

	maxSpeedTestSize = 1 << 30
)

func generateSelfSignedCert(certPath, keyPath string) error {
	// 创建目录
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	keyDir := filepath.Dir(keyPath)
	if keyDir != certDir {
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(certValidYears, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certOrganization},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", hostname, "*.localhost"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv4(0, 0, 0, 0),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer func() {
		if cerr := certFile.Close(); cerr != nil {
			log.Printf("close cert file: %v", cerr)
		}
	}()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer func() {
		if cerr := keyFile.Close(); cerr != nil {
			log.Printf("close key file: %v", cerr)
		}
	}()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	log.Printf("Generated self-signed certificate: %s", certPath)
	log.Printf("Certificate valid from %s to %s", notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	log.Printf("Certificate includes: DNS=localhost,%s,*.localhost IP=127.0.0.1,0.0.0.0,::1", hostname)

	return nil
}

func ensureCertExists(certPath, keyPath string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			log.Printf("Using existing certificate: %s", certPath)
			return nil
		}
		log.Printf("Existing certificate invalid, regenerating...")
	}
	log.Printf("Generating self-signed certificate...")
	return generateSelfSignedCert(certPath, keyPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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
	downloadCnt atomic.Int64
	totalBytes  atomic.Int64
	whitelist   []*net.IPNet
	allowAll    bool
}

func NewSpeedTestManager(whitelistStr string) *SpeedTestManager {
	m := &SpeedTestManager{}
	m.parseWhitelist(whitelistStr)
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
		// 如果不是 CIDR 格式，当作单个 IP 处理
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

	// 提取 IP（去掉端口）
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

func (m *SpeedTestManager) recordDownload(bytes int64) {
	m.downloadCnt.Add(1)
	m.totalBytes.Add(bytes)
}

func (m *SpeedTestManager) getStats() (downloads, totalBytes int64) {
	return m.downloadCnt.Load(), m.totalBytes.Load()
}

func parseSizeParam(s string) (int64, error) {
	if s == "" {
		return defaultSpeedTestSize, nil
	}

	s = strings.TrimSpace(strings.ToUpper(s))
	var mult int64 = 1

	switch {
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
	httpServer   *http.Server
	http3Server  *http3.Server
	tlsConfig    *tls.Config
	certPath     string
	keyPath      string
	shutdownMu   sync.Mutex
	shutdownCh   chan struct{}
	speedTestMgr *SpeedTestManager
}

type Config struct {
	Addr           string
	CertPath       string
	KeyPath        string
	SpeedWhitelist string
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

	if err := ensureCertExists(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("ensure certificate: %w", err)
	}

	s := &Server{
		certPath:     certPath,
		keyPath:      keyPath,
		shutdownCh:   make(chan struct{}),
		speedTestMgr: NewSpeedTestManager(cfg.SpeedWhitelist),
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
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=test%dMB.bin", size>>20))

	http.ServeContent(&statsWriter{
		ResponseWriter: w,
		onDone:         func(n int64) { s.speedTestMgr.recordDownload(n) },
	}, r, "test.bin", time.Now(), &virtualReader{size: size})
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
	onDone func(int64)
	n      int64
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
	downloads, total := s.speedTestMgr.getStats()
	w.Header().Set("Content-Type", "application/json")
	_, err := fmt.Fprintf(w, `{"downloads":%d,"total_bytes":%d,"total_mb":%.2f}`, downloads, total, float64(total)/(1<<20))
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

	var tlsInfo struct {
		Version     string
		CipherSuite string
	}
	if tlsState := r.TLS; tlsState != nil {
		tlsInfo.Version = tlsVersionName(tlsState.Version)
		tlsInfo.CipherSuite = tlsCipherSuiteName(tlsState.CipherSuite)
	} else {
		tlsInfo.Version = "N/A"
		tlsInfo.CipherSuite = "N/A"
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	proto := r.Proto
	if r.ProtoMajor == 3 {
		proto = "HTTP/3"
	}

	realIP := getRealIP(r)
	downloads, totalBytes := s.speedTestMgr.getStats()

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTPS Server</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px 20px; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #eee; min-height: 100vh; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #4fc3f7; margin-bottom: 8px; font-size: 2em; }
        .version { color: #888; font-size: 0.9em; margin-bottom: 24px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; backdrop-filter: blur(10px); }
        .card h2 { color: #4fc3f7; font-size: 1.1em; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        table { width: 100%; border-collapse: collapse; }
        td { padding: 6px 0; font-size: 0.9em; }
        td:first-child { color: #888; width: 40%; }
        td:last-child { word-break: break-all; }
        .endpoints { list-style: none; }
        .endpoints li { padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; gap: 12px; }
        .endpoints li:last-child { border-bottom: none; }
        .endpoints code { background: rgba(79,195,247,0.15); color: #4fc3f7; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; white-space: nowrap; }
        .endpoints a { color: #4fc3f7; text-decoration: none; }
        .endpoints a:hover { text-decoration: underline; }
        .method { font-size: 0.7em; padding: 2px 6px; border-radius: 3px; background: #2e7d32; color: #fff; }
        .desc { color: #aaa; font-size: 0.85em; flex: 1; }
        .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
        .stat-item { text-align: center; padding: 12px; background: rgba(255,255,255,0.03); border-radius: 8px; }
        .stat-value { font-size: 1.5em; color: #4fc3f7; font-weight: 600; }
        .stat-label { font-size: 0.75em; color: #888; margin-top: 4px; }
        .headers-list { max-height: 200px; overflow-y: auto; }
        .header-item { padding: 4px 0; font-size: 0.8em; }
        .header-key { color: #81c784; }
        .header-val { color: #aaa; word-break: break-all; }
        footer { text-align: center; margin-top: 40px; color: #555; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 HTTPS Server</h1>
        <p class="version">Version: ` + Version + ` | Build: ` + BuildDate + `</p>
        
        <div class="grid">
            <div class="card">
                <h2>📡 Connection</h2>
                <table>
                    <tr><td>Protocol</td><td>` + proto + `</td></tr>
                    <tr><td>TLS Version</td><td>` + tlsInfo.Version + `</td></tr>
                    <tr><td>Cipher Suite</td><td>` + tlsInfo.CipherSuite + `</td></tr>
                    <tr><td>Server Host</td><td>` + hostname + `</td></tr>
                    <tr><td>Your IP</td><td>` + realIP + `</td></tr>
                    <tr><td>Remote Addr</td><td>` + r.RemoteAddr + `</td></tr>
                    <tr><td>Server Time</td><td>` + time.Now().Format("2006-01-02 15:04:05 MST") + `</td></tr>
                </table>
            </div>
            
            <div class="card">
                <h2>📊 Statistics</h2>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value">` + fmt.Sprintf("%d", downloads) + `</div>
                        <div class="stat-label">Downloads</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">` + fmt.Sprintf("%.2f", float64(totalBytes)/(1<<20)) + `</div>
                        <div class="stat-label">Total MB</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>🔗 Endpoints</h2>
                <ul class="endpoints">
                    <li><code><a href="/health">/health</a></code><span class="method">GET</span><span class="desc">Health check</span></li>
                    <li><code><a href="/stats">/stats</a></code><span class="method">GET</span><span class="desc">Download statistics</span></li>
                    <li><code><a href="/download">/download</a></code><span class="method">GET</span><span class="desc">Speed test (size param)</span></li>
                    <li><code>/generate_204</code><span class="method">GET</span><span class="desc">Captive portal check</span></li>
                </ul>
            </div>
            
            <div class="card">
                <h2>📋 Request Headers</h2>
                <div class="headers-list">
                    <div class="header-item"><span class="header-key">User-Agent:</span> <span class="header-val">` + r.UserAgent() + `</span></div>
                    <div class="header-item"><span class="header-key">Accept:</span> <span class="header-val">` + r.Header.Get("Accept") + `</span></div>
                    <div class="header-item"><span class="header-key">Accept-Language:</span> <span class="header-val">` + r.Header.Get("Accept-Language") + `</span></div>
                    <div class="header-item"><span class="header-key">Accept-Encoding:</span> <span class="header-val">` + r.Header.Get("Accept-Encoding") + `</span></div>
                    <div class="header-item"><span class="header-key">Connection:</span> <span class="header-val">` + r.Header.Get("Connection") + `</span></div>
                </div>
            </div>
        </div>
        
        <footer>
            Powered by Go | TLS 1.3 Only | HTTP/2 & HTTP/3
        </footer>
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

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tlsListener := tls.NewListener(listener, s.httpServer.TLSConfig)

	log.Printf("HTTPS server on %s (HTTP/2 + HTTP/3)", s.httpServer.Addr)

	errCh := make(chan error, 2)

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

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var errs []error
	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http2: %w", err))
	}
	if err := s.http3Server.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http3: %w", err))
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

	cfg := Config{
		Addr:           getEnvWithDefault("SERVER_ADDR", defaultAddr),
		CertPath:       getEnvWithDefault("CERT_PATH", "./certs/server.crt"),
		KeyPath:        getEnvWithDefault("KEY_PATH", "./certs/server.key"),
		SpeedWhitelist: speedWhitelist,
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
