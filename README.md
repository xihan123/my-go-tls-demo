# my-go-tls-demo

HTTPS server with TLS 1.3, HTTP/2 and HTTP/3 support.

## Usage

```bash
go run main.go
```

Server starts on `:443` by default.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDR` | `:443` | Listen address |
| `CERT_PATH` | `./certs/server.crt` | Certificate path |
| `KEY_PATH` | `./certs/server.key` | Private key path |
| `SPEED_WHITELIST` | `*` | IP whitelist for speed test |

Self-signed certificates are auto-generated on first run.

### Speed Test Whitelist

Control who can access `/download` endpoint:

**Via environment variable:**
```bash
# Allow all (default)
SPEED_WHITELIST=*

# Single IP
SPEED_WHITELIST=192.168.1.100

# Multiple IPs
SPEED_WHITELIST=192.168.1.100,10.0.0.50

# CIDR ranges
SPEED_WHITELIST=192.168.1.0/24,10.0.0.0/8
```

**Via command line:**

```bash
# Override environment variable
./my-go-tls-demo -whitelist "192.168.1.0/24,10.0.0.50"
./my-go-tls-demo -w "192.168.1.0/24"  # shorthand
```

## Endpoints

- `GET /` - Server info
- `GET /health` - Health check
- `GET /download` - Speed test file download (default 100MB)
- `GET /stats` - Download statistics

## Speed Test

Download a test file for bandwidth measurement:

```bash
# Default 100MB
curl -O https://localhost:443/download

# Custom size: 50MB, 500KB, 1GB, etc.
curl -O "https://localhost:443/download?size=50MB"

# Multi-threaded download (aria2c)
aria2c -x 16 -s 16 https://localhost:443/download?size=500MB
```

Supported size units: `B`, `KB`, `MB`, `GB` (max 1GB)

Features:

- Zero disk/memory usage (virtual data source)
- Range request support (multi-threaded download)
- Automatic HTTP/2 and HTTP/3 support
