# PacketStream Autonomous Python Client

An independent, headless, pure-Python CLI client for [PacketStream](https://packetstream.io/) exit nodes, reverse engineered from the official Android application (`packeter-v2.5.1-8.apk`).

This tool allows you to run PacketStream bandwidth sharing directly on Linux, macOS, Windows, Raspberry Pi, Docker, or any headless server **without needing Android, an emulator, or GUI**.

---

## ⚡ Key Highlights

- **100% Pure Python**: Uses standard library modules (`asyncio`, `ssl`, `urllib`, `socket`, `struct`). **Zero required pip dependencies**.
- **Complete Protocol Interoperability**: Exactly replicates the Android `libgojni.so` exit node engine (`github.com/packetstream/ecosystem/exit-node/mobilecore`).
- **Hashicorp Yamux v0 Multiplexer**: Native pure-Python implementation of Hashicorp Yamux multiplexing with flow control and window management.
- **Dual Gateway Endpoints**: Concurrently maintains both the HTTP proxy tunnel (`client.packetstream.io:30944`) and the SOCKS5 proxy tunnel (`client.packetstream.io:30946`).
- **Enterprise-Grade Security (`BlockLocalAccess`)**: Replicates official security rules to block LAN/private subnets (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, CGNAT `100.64.0.0/10`, IPv6 local, and local TLDs) to prevent SSRF and internal network exposure.
- **Live Terminal Dashboard**: Real-time ANSI dashboard showing active tunnels, stream count, current bandwidth transfer rates, and total shared data.

---

## 🔬 Reverse Engineering Summary

Decompilation of `packeter-v2.5.1-8.apk` revealed that the Android app is a thin Kotlin wrapper around a compiled Go shared library (`libgojni.so` generated with `gomobile bind`).

### 1. Authentication (`parseAuthCode`)
- The login code from `https://app.packetstream.io/dashboard/client_auth` is a **base64-encoded string** formatted as:
  ```
  base64("<user_id>:<secret_token>")
  ```
- `user_id`: Positive integer (> 0)
- `secret_token`: Alphanumeric token string (minimum 3 characters)

### 2. Admission Service (`fetchToken`)
- **HTTP Request**:
  ```http
  GET /exitnode/ipinfo/<user_id>?client_version=v2.5.1&os=android&arch=amd64&update_mode=android_sideload HTTP/1.1
  Host: api.packetstream.io
  User-Agent: Go-http-client/1.1
  X-PacketStream-Installation-ID: <uuid>
  ```
- **Response**:
  ```json
  {
    "status": 200,
    "message": "success",
    "data": "<jwt_session_token>"
  }
  ```
  *(Note: Non-residential or datacenter IPs receive HTTP 403 with retry delay `300000000000` ns = 5 minutes).*

### 3. Multiplexing & Handshake (`Handshake` + `authenticate`)
The client runs two endpoints in parallel:
1. **HTTP Proxy**: `client.packetstream.io:30944`
2. **SOCKS5 Proxy**: `client.packetstream.io:30946`

Connection handshake sequence:
1. **TLS Handshake**: Wraps TCP connection with TLS, setting ALPN `NextProtos`:
   ```
   packetstream-packeter-mux/1
   ```
2. **Authentication Frame**: Client writes admission token followed by newline:
   ```
   <jwt_session_token>\n
   ```
3. **Acknowledgement**: Client reads exactly 1 byte. Server sends `0x00` on success.
4. **Yamux Server Session**: The TLS connection is wrapped into a **Hashicorp Yamux Server** session (`yamux.Server(tlsConn)`).

### 4. Proxy Stream Handling (`acceptRequests` / `HandleRequest` / `tunnel.Pipe`)
The PacketStream gateway opens multiplexed Yamux streams to the client when routing user traffic:
- **Port 30944 (HTTP)**: Accepts HTTP `CONNECT host:port` or plain HTTP requests, drains headers, verifies target host with `BlockLocalAccess`, dials target via TCP, responds with `HTTP/1.1 200 Connection Established\r\n\r\n`, and pipes data bi-directionally.
- **Port 30946 (SOCKS5)**: Accepts `VER=5, CMD=1, RSV=0, ATYP`, parses destination address, verifies with `BlockLocalAccess`, dials target, responds with SOCKS5 success frame `\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00`, and pipes data.

### 5. Automatic Token Refresh (`refreshToken` / `sendRefresh`)
- Periodically before token expiry, the client opens a stream on the existing Yamux session (`session.OpenStream()`), writes `<refreshed_jwt>\n`, and reads `0x00` ack.
- If the public IP changes, tunnels are closed and re-established with the new IP.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher.
- A residential Internet connection (PacketStream requires residential IP addresses).

### 1. Get Your Login Code
1. Log in to your [PacketStream Dashboard](https://app.packetstream.io/dashboard).
2. Go to [Client Auth Page](https://app.packetstream.io/dashboard/client_auth).
3. Copy your Login Code (e.g. `MTIzNDU6YWJjZGVmZ2hpams=`).

### 2. Run the Client

**Interactive Mode:**
```bash
python3 main.py
```
*(Prompts for your Login Code and starts sharing)*

**Direct CLI Flag:**
```bash
python3 main.py -a "MTIzNDU6YWJjZGVmZ2hpams="
```

**Using Environment Variable:**
```bash
export PACKETSTREAM_AUTH_CODE="MTIzNDU6YWJjZGVmZ2hpams="
python3 main.py
```

---

## 🖥️ CLI Options

```text
usage: main.py [-h] [-a AUTH_CODE] [--socks-only] [--http-only]
               [--client-version CLIENT_VERSION] [--os OS] [--arch ARCH]
               [--status-interval STATUS_INTERVAL] [-v] [--no-dashboard]

options:
  -h, --help            Show this help message and exit
  -a, --auth-code CODE  Base64-encoded login code from PacketStream dashboard
  --socks-only          Run only SOCKS5 tunnel (:30946)
  --http-only           Run only HTTP tunnel (:30944)
  --client-version VER  Client version reported to PacketStream (default: v2.5.1)
  --os OS               OS reported to PacketStream (default: android)
  --arch ARCH           Architecture reported to PacketStream (default: amd64)
  --status-interval SEC Dashboard refresh interval in seconds (default: 1.0)
  -v, --verbose         Enable debug logging
  --no-dashboard        Disable ANSI dashboard (runs in line-by-line log mode)
```

---

## 📊 Live Dashboard Preview

```text
  ____            _        _   ____  _                              
 |  _ \ __ _  ___| | _____| |_/ ___|| |_ _ __ ___  __ _ _ __ ___  
 | |_) / _` |/ __| |/ / _ \ __\___ \| __| '__/ _ \/ _` | '_ ` _ \ 
 |  __/ (_| | (__|   <  __/ |_ ___) | |_| | |  __/ (_| | | | | | |
 |_|   \__,_|\___|_|\_\___|\__|____/ \__|_|  \___|\__,_|_| |_| |_|
            Autonomous Python Exit Node - Client v2.5.1

=================================================================
  User ID:            12345
  Detected IP:        203.0.113.42
  Status:             Online & Sharing Bandwidth
  Active Tunnels:     2 / 2 (:30944 HTTP, :30946 SOCKS5)
  Active Streams:     3
  Total Served:       156 connections
-----------------------------------------------------------------
  Data Uploaded:      48.21 MB            Rate: ↑ 124.50 KB/s
  Data Downloaded:    19.45 MB            Rate: ↓ 42.10 KB/s
  Session Uptime:     01:24:10
=================================================================
  [Press Ctrl+C to Stop]
```

---

## 🧪 Running Automated Tests

Run the built-in test suite (tests authentication, security filtering, and Yamux pipeline):
```bash
python3 -m unittest -v tests/test_packetstream.py
```

---

## 📦 Project Architecture

```
packetstream/
├── __init__.py         # Package entry
├── auth.py             # Auth code decoding, JWT parsing, and admission API client
├── yamux.py            # Pure-Python Hashicorp Yamux v0 multiplexer
├── security.py         # BlockLocalAccess (private IP & local TLD protection)
├── proxy.py            # HTTP CONNECT & SOCKS5 stream proxy handlers
├── tunnel.py           # TLS ALPN handshake & Packetermux session setup
├── client.py           # Core client orchestrator & endpoint workers
└── cli.py              # CLI parser & terminal dashboard

main.py                 # Direct executable entrypoint
packetstream-cli.py     # Alternative entrypoint script
tests/
└── test_packetstream.py# Comprehensive automated test suite
```

---

## 🔒 Security & Privacy Notice

This implementation faithfully reproduces PacketStream's `BlockLocalAccess` security model:
- Disallows proxy connections targeting loopback (`127.0.0.0/8`, `::1`), private LANs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, carrier-grade NAT, and local domain names (`.local`, `.internal`, `.lan`, etc.).
- Performs DNS pre-resolution before dialing to protect your local network from SSRF attacks.
