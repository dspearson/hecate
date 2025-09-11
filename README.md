# Hecate

A secure file archiving tool that encrypts files/directories using modern cryptography and splits the encryption key using Shamir Secret Sharing, with shares encoded as BIP39 mnemonics and QR codes.

## Features

- 🔐 **Strong Encryption**: XChaCha20-Poly1305 authenticated encryption via libsodium secretstream
- 🧩 **Shamir Secret Sharing**: Split keys into n shares, require k to decrypt
- 💬 **Human-Friendly**: Shares encoded as BIP39 mnemonic phrases
- 📱 **QR Codes**: Each share generates a QR code for easy storage/distribution
- 🌐 **Remote Storage**: Upload encrypted archives to Hecate server via secure WebSocket
- 📦 **Efficient Compression**: Zstandard compression before encryption
- 🔄 **True Streaming**: Memory-efficient pipeline with 1MB chunks, no file size limits
- 🔒 **Transport Security**: TLS with EC certificates (P-256)
- 🔑 **Authentication**: Preshared key authentication with Argon2 hashing
- 🎯 **Certificate Pinning**: Optional SHA256 certificate fingerprint validation
- ⚙️ **Configuration Files**: Support for server aliases and per-server settings
- 📦 **Build-Time Embedding**: Compile credentials directly into binary for deployment

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/dspearson/hecate.git
cd hecate

# Build release binaries
cargo build --release

# Binaries will be at:
# - ./target/release/hecate (client)
# - ./target/release/hecate-server (server)
```

### Requirements

- Rust edition 2024
- libsodium development libraries
- For development: Nix flakes with direnv (optional but recommended)

## Configuration

Hecate supports configuration files to set defaults and define server aliases. Configuration files are checked in the following order:

1. Path specified via `HECATE_CONFIG` environment variable
2. `.hecate.toml` in current directory
3. `~/.config/hecate/config.toml` (XDG standard)
4. `~/.config/hecate.toml`
5. `~/.hecate.toml`
6. `/etc/hecate/config.toml` (system-wide)

### Generate Sample Config

```bash
hecate --generate-config
# Creates config at ~/.config/hecate/config.toml
```

### Config File Format

```toml
[defaults]
shares_needed = 2
total_shares = 5
server = "localhost:10112"
verbose = false
output_dir = "/home/user/encrypted"  # Optional default output directory

[[servers]]
name = "local"
address = "localhost"
port = 10112
default = true
# auth_key = "optional-key-for-this-server"

[[servers]]
name = "backup"
address = "backup.example.com"  
port = 10112
default = false
auth_key = "your-secret-key-here"

[servers.tls]
verify = true
# Optional: Pin to specific certificate fingerprint
# fingerprint = "SHA256:1234567890abcdef..."

[[servers]]
name = "cloud"
address = "cloud.provider.com"
port = 10112
auth_key = "different-key-for-cloud"

[auth]
# Default authentication key for servers that don't specify one
default_key = "default-preshared-key"
```

### Using Config

```bash
# Use specific config file
hecate --config ~/my-config.toml files/

# Use server alias from config
hecate --online --list --server backup

# Override config with CLI args (CLI takes precedence)
hecate files/ --shares-needed 4 --total-shares 8
```

## Usage

### Basic Encryption

```bash
# Encrypt a file (default 2-of-5 shares)
hecate important.pdf
# Creates: 2025-09-04-1234567890.hecate
# Keys: 2025-09-04-1234567890-key-01.png through key-05.png

# With authentication key (for protected servers)
hecate important.pdf --online --name backup --auth-key "secret-key"

# Encrypt a directory with custom sharing (3-of-7)
hecate documents/ --shares-needed 3 --total-shares 7

# Specify output name
hecate data/ --output backup-2024.hecate
# Creates: backup-2024.hecate
# Keys: backup-2024-key-01.png through backup-2024-key-05.png
```

### Decryption

```bash
# Decrypt using key files (QR codes)
hecate backup.hecate --unpack --key key-01.png --key key-02.png

# Interactive mode - will prompt for shares
hecate backup.hecate --unpack

# Decrypt to tar.zst without extracting
hecate backup.hecate --decrypt --key key-01.png --key key-02.png
```

### Remote Storage with Hecate Server

```bash
# Upload to server (automatic .hecate extension)
hecate documents/ --online --name my-backup --server backup.example.com:10112

# List available files
hecate --online --list --server backup.example.com:10112

# Download and decrypt (no need to specify .hecate extension)
hecate --online --unpack --name my-backup --server backup.example.com:10112 \
  --key my-backup-key-01.png --key my-backup-key-02.png

# With authentication
export MERCURY_AUTH_KEY="your-secret-key"
hecate documents/ --online --name my-backup --server backup.example.com:10112

# With TLS certificate validation options
hecate --online --list --server backup.example.com:10112 --no-verify-tls  # Skip cert validation
hecate --online --list --server backup.example.com:10112 \
  --tls-fingerprint "SHA256:1234567890abcdef..."  # Pin to specific certificate
```

## How It Works

1. **Archive Creation**: Files are packed into a tar archive
2. **Compression**: Archive is compressed using Zstandard
3. **Key Generation**: Random 256-bit encryption key is generated
4. **Streaming Encryption**: Data flows through pipeline: tar → zstd → encrypt → chunks
5. **Secret Sharing**: Key is split into shares using Shamir's algorithm
6. **Share Encoding**: Each share is encoded as BIP39 mnemonic words
7. **QR Generation**: QR codes are created for each share
8. **Network Transfer**: Streamed via WebSocket in 1MB chunks (if online)

### Share Format

Each share is encoded as BIP39 mnemonic words (24 words per share) with the share index embedded in the encoding. The shares include random padding for security benefits, ensuring that individual shares reveal nothing about the encryption key.

## Hecate Server

The Hecate server provides secure remote storage for encrypted archives.

### Running the Server

```bash
cd server
cargo build --release

# Generate configuration file
./target/release/hecate-server --generate-config > server.toml

# Edit server.toml to configure:
# - Storage paths and database location
# - TLS certificates
# - Authentication settings
# - User quotas and limits

# Run with configuration
./target/release/hecate-server --config server.toml

# With authentication (preshared key)
MERCURY_AUTH_KEY="your-secret-key" ./target/release/hecate-server --config server.toml

# With TLS (generate EC certificate)
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365
./target/release/hecate-server --config server.toml
```

### Server Features

- **Secure Storage**: Accepts encrypted archives via WebSocket (TLS required)
- **Authentication**: Preshared key authentication with Argon2 hashing
- **Health Monitoring**: HTTP endpoints for health checks (/health, /livez, /readyz, /metrics)
- **Streaming Transfer**: Memory-efficient 1MB chunk transfers
- **Collision Handling**: Automatic filename deduplication with timestamps/UUIDs
- **Configuration**: TOML-based configuration or command-line arguments

### Server Options

- `--config <FILE>`: Configuration file path
- `--generate-config`: Generate example configuration
- `--store <PATH>`: Directory to store encrypted files (default: `./storage`)
- `--port <PORT>`: WebSocket port (default: `10112`)
- `--tls-cert <FILE>`: TLS certificate file (enables TLS)
- `--tls-key <FILE>`: TLS private key file
- `--verbose`: Enable verbose logging
- Environment: `MERCURY_AUTH_KEY` for preshared key authentication

### Protocol

The server uses WebSocket (with TLS) for communication:

1. **Connection**: WebSocket upgrade (wss:// for TLS, ws:// for plain)

2. **Authentication** (if server requires it):
   - Client: `AUTH <preshared-key>`
   - Server: `OK` or `ERROR Invalid authentication`

3. **Upload** (streaming in 1MB chunks):
   - Client: `NAME <filename>` - Propose a filename
   - Server: `ACCEPT <actual-filename>` - May differ if collision
   - Client: `DATA`
   - Client: Sends binary chunks (max 1MB each)
   - Client: Sends `END` to finish
   - Server: `OK <bytes-received>`

4. **List**:
   - Client: `LIST`
   - Server: Sends filename per line, then `END`

5. **Download** (streaming in 1MB chunks):
   - Client: `GET <filename>`
   - Server: `DATA` or `ERROR`
   - Server: Sends binary chunks (max 1MB each)
   - Server: Sends `END` to finish

## Security Considerations

- **Key Generation**: Random 256-bit key using libsodium's secure RNG
- **Authenticated Encryption**: XChaCha20-Poly1305 AEAD prevents tampering
- **Forward Secrecy**: Each encryption uses a unique nonce
- **Transport Security**: TLS with EC certificates (P-256)
- **Authentication**: Preshared key authentication with Argon2 hashing
- **Memory Safety**: Written in Rust with no unsafe code
- **True Streaming**: Pipeline processes data in 1MB chunks without buffering entire archives
- **Share Security**: Individual shares reveal nothing about the key
- **Random Padding**: Shares include random padding for security benefits
- **No Size Limits**: Streaming architecture handles files of any size
- **Certificate Pinning**: Optional SHA256 fingerprint validation for enhanced security

## Examples

### Family Photo Backup

```bash
# Create encrypted backup with 2-of-3 sharing
hecate photos/ --shares-needed 2 --total-shares 3 --output photos-2024.hecate

# Give share 1 to spouse, share 2 to parent, keep share 3
# Any two family members can recover the photos
```

### Corporate Document Archive

```bash
# Create archive requiring 3 of 5 executives to decrypt
hecate sensitive-docs/ --shares-needed 3 --total-shares 5 --online \
  --name quarterly-report --server corp-backup.internal:10112

# Distribute shares to 5 executives
# Any 3 can collaborate to recover documents
```

### Personal Backup

```bash
# Create backup with shares as QR codes
hecate important-files/ --output personal-backup.hecate

# Print QR codes and store in:
# - Safe deposit box
# - Home safe  
# - Office
# - Trusted friend
# - Bank vault
```

## Authentication

Hecate supports authentication for remote servers using preshared keys:

### Configuration Methods

1. **Command Line**: `--auth-key "your-secret-key"`
2. **Environment Variable**: `MERCURY_AUTH_KEY="your-secret-key"`
3. **Config File**: See config file format above
4. **Compile-Time Embedding**: Build with environment variables:
   ```bash
   HECATE_DEFAULT_AUTH_KEY="production-key" \
   HECATE_DEFAULT_SERVER="server.example.com:10112" \
   cargo build --release
   ```

### Priority Order

1. Command-line `--auth-key` flag
2. `MERCURY_AUTH_KEY` environment variable
3. Compile-time embedded key
4. Server-specific key from config file
5. Default key from config file

## Building from Source

### Prerequisites

```bash
# Ubuntu/Debian
apt-get install libsodium-dev pkg-config

# macOS
brew install libsodium

# Arch Linux
pacman -S libsodium
```

### Build

```bash
cargo build --release
cargo test  # Run tests
```

## Contributing

Contributions are welcome! Please ensure:
- Code follows Rust idioms
- British English spelling in comments/docs
- No compiler warnings
- Tests pass
- Security-first design

## Licence

ISC Licence - see LICENCE file

## Author

Dominic Pearson <dsp@technoanimal.net>

## Acknowledgments

- libsodium/NaCl developers for cryptographic primitives
- Adi Shamir for the secret sharing algorithm
- BIP39 authors for mnemonic encoding standard