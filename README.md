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

Self-signed certificates are auto-generated on first run.

## Endpoints

- `GET /` - Server info
- `GET /health` - Health check
