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
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	defaultAddr       = ":443"
	shutdownTimeout   = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20
	certOrganization  = "Self-Signed Certificate"
	certValidYears    = 10
	rsaKeyBits        = 4096
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

type Server struct {
	httpServer  *http.Server
	http3Server *http3.Server
	tlsConfig   *tls.Config
	certPath    string
	keyPath     string
	shutdownMu  sync.Mutex
	shutdownCh  chan struct{}
}

type Config struct {
	Addr     string
	CertPath string
	KeyPath  string
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
		certPath:   certPath,
		keyPath:    keyPath,
		shutdownCh: make(chan struct{}),
	}

	handler := s.createHandler()

	// TCP TLS配置 - 只支持h2和http/1.1
	tcpTLSConfig := &tls.Config{
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

	// HTTP/3 TLS配置 - 需要http3.ConfigureTLSConfig
	quicTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		GetCertificate:   s.getCertificate,
	}
	s.tlsConfig = http3.ConfigureTLSConfig(quicTLSConfig)

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		TLSConfig:         tcpTLSConfig,
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
		log.Printf("[%s] %s %s %s", r.Method, r.URL.Path, r.RemoteAddr, r.Proto)
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

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTTPS Server</title>
    <style>
        body { font-family: system-ui, sans-serif; padding: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #4fc3f7; }
        table { border-collapse: collapse; margin: 20px 0; }
        td { padding: 8px 16px; border-bottom: 1px solid #333; }
        td:first-child { color: #888; }
    </style>
</head>
<body>
    <h1>HTTPS Server</h1>
    <table>
        <tr><td>Protocol</td><td>` + proto + `</td></tr>
        <tr><td>TLS</td><td>` + tlsInfo.Version + `</td></tr>
        <tr><td>Cipher</td><td>` + tlsInfo.CipherSuite + `</td></tr>
        <tr><td>Host</td><td>` + hostname + `</td></tr>
        <tr><td>Remote</td><td>` + r.RemoteAddr + `</td></tr>
        <tr><td>Time</td><td>` + time.Now().Format("2006-01-02 15:04:05") + `</td></tr>
    </table>
    <p>Endpoint: <code>/health</code></p>
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
	_ = godotenv.Load()

	cfg := Config{
		Addr:     getEnvWithDefault("SERVER_ADDR", defaultAddr),
		CertPath: getEnvWithDefault("CERT_PATH", "./certs/server.crt"),
		KeyPath:  getEnvWithDefault("KEY_PATH", "./certs/server.key"),
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
