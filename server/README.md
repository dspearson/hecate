# Hecate Server

A secure storage server for Hecate encrypted archives with WebSocket streaming, TLS support, and multi-client authentication.

**Note**: This is a hobby project and may contain bugs. Use at your own risk. Not suitable for production use without thorough testing and security review.

## Features

- **WebSocket Streaming**: Efficient file transfer with 1MB chunked streaming
- **TLS Support**: Secure connections with EC (P-256) certificates
- **Multi-Client Authentication**: Per-client credentials with Argon2id password hashing
- **Health Monitoring**: Built-in health check endpoint
- **File Management**: List, upload, and download encrypted archives
- **Automatic Naming**: Collision detection with timestamp-based renaming
- **Configurable**: TOML configuration file support
- **Service Ready**: systemd service file included

## Installation

### From Source

```bash
cargo build --release
./target/release/hecate-server --generate-config > hecate-server.toml
```

### Generate TLS Certificate

```bash
# EC certificate (recommended)
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

## Usage

### Basic Server

```bash
# With configuration file
hecate-server --config hecate-server.toml

# Or with command-line arguments
hecate-server --store /var/hecate-server --port 10112 \
  --tls-cert cert.pem --tls-key key.pem
```

### Authentication Setup

#### Single Key Mode
```bash
# Simple preshared key
MERCURY_AUTH_KEY="your-secret-key" hecate-server --config hecate-server.toml
```

#### Multi-Client Mode
```bash
# Generate password hash
cargo run --bin hash_password -- "client-password"

# Create auth configuration
cat > auth.json << EOF
{
  "clients": [
    {
      "client_id": "alice",
      "key_hash": "$argon2id$..."
    }
  ]
}
EOF

# Run with auth config
hecate-server --config hecate-server.toml --auth-config auth.json
```

## Configuration

Example `hecate-server.toml`:
```toml
store_path = "/var/hecate-server/storage"
port = 10112
verbose = false

[tls]
cert_path = "/etc/hecate-server/cert.pem"
key_path = "/etc/hecate-server/key.pem"

[limits]
max_file_size_mb = 10240  # 10GB
max_concurrent_clients = 100

[auth]
auth_key = "optional-preshared-key"
```

## Protocol

Mercury uses a simple text-based WebSocket protocol:

### Upload
```
Client: AUTH <key>
Server: OK
Client: NAME <filename>
Server: ACCEPT <actual-filename>
Client: DATA
Client: <binary chunks>
Client: END
Server: OK <bytes-received>
```

### List Files
```
Client: LIST
Server: <filename1>
Server: <filename2>
Server: END
```

### Download
```
Client: GET <filename>
Server: DATA
Server: <binary chunks>
Server: END
```

## Deployment

### Systemd Service

```bash
sudo cp hecate-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hecate-server
sudo systemctl start hecate-server
```

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/hecate-server /usr/local/bin/
EXPOSE 10112
CMD ["hecate-server", "--config", "/etc/hecate-server/hecate-server.toml"]
```

## Security Considerations

- Always use TLS in production
- Store password hashes, never plaintext passwords
- Use strong, unique passwords for each client
- Regularly rotate authentication credentials
- Set appropriate file size limits
- Monitor failed authentication attempts
- Use filesystem permissions to protect stored files

## Licence

ISC Licence

## Author

Dominic Pearson <dsp@technoanimal.net>