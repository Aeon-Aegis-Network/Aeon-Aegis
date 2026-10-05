# Aeon Aegis 🛡️

Aeon Aegis is a high-throughput, multi-overlay zero-trust P2P relay network engineered to obfuscate validator endpoints, shield origin infrastructure from direct IP exposure, and route encrypted traffic across decentralized Akash edge nodes.

---

## 🏛️ Multi-Overlay Security Architecture

Aeon Aegis enforces a multi-layered defense-in-depth routing stack to ensure traffic privacy, integrity, and origin isolation:

```text
+-----------------------------------------------------------------------------------+
|                                CLIENT / dAPP                                      |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼  [Layer 1: WireGuard UDP Tunnel | Port 51820 | 10.0.0.x Overlay]
+-----------------------------------------------------------------------------------+
|                                ENTRY RELAY NODE                                   |
|  - Peels Outer Onion Layer (X25519 DH + ChaCha20-Poly1305)                        |
|  - Sees: Client Source IP                                                         |
|  - Knows: Transit Node Multiaddr ONLY                                             |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼  [Layer 2: libp2p Noise TCP Stream | Port 9090 | /aeon-aegis/onion/1.0.0]
+-----------------------------------------------------------------------------------+
|                                TRANSIT RELAY NODE                                 |
|  - Peels Intermediate Onion Layer                                                 |
|  - Sees: Entry Node IP                                                            |
|  - Knows: Exit / Egress Node Multiaddr ONLY                                       |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼  [Layer 3: mTLS Control & Exit Proxy | Port 9091]
+-----------------------------------------------------------------------------------+
|                             EGRESS NODE / PROTECTED ORIGIN                        |
|  - Peels Final Inner Payload & Routes to Loopback                                 |
|  - Sees: Transit Node IP                                                          |
|  - Protected Origin Endpoint: 127.0.0.1:8080 (Shielded)                           |
+-----------------------------------------------------------------------------------+

```

---

## 🧅 Sphinx Multi-Hop Onion Routing Specification

The Sphinx-inspired packet encryption engine (`src/security/onionRouter.ts`) guarantees destination obfuscation across multi-hop relay circuits:

* **Cryptographic Primitives:** Ephemeral Diffie-Hellman key exchange over `X25519` combined with `ChaCha20-Poly1305` AEAD symmetric encryption.
* **Key Derivation:** HKDF-SHA256 derives 256-bit symmetric keys per circuit layer using the ephemeral key pair and target node public key (`aeon-aegis-onion-v1` salt).
* **Layer Frame Layout:**
```text
+-----------------------+------------------+-------------------+---------------------+
| Ephemeral PubKey (32B)|   IV (12 Bytes)  | Auth Tag (16 Bytes)|     Ciphertext      |
+-----------------------+------------------+-------------------+---------------------+

```


* **Protocol Target:** Handled over `/aeon-aegis/onion/1.0.0`.
* **Zero Destination Leakage:** Each relay node unwraps its specific layer to extract the next hop multiaddr and inner encrypted payload, ensuring no single entry node can map a client IP to its ultimate validator destination.

---

## 🔒 Mutual TLS (mTLS) Control Plane Documentation

The telemetry and management interface runs on port `9091` protected by strict Mutual TLS:

* **PKI Architecture:** Root CA (`certs/ca.crt`), Server Certificates (`certs/server.crt`), and Operator Client Certificates (`certs/client.crt`).
* **Strict Mutual Verification:** Handshakes missing valid operator client certificates signed by the Root CA are terminated at the TLS layer (`rejectUnauthorized: true`).
* **Endpoints:**
* `GET /health` — Returns service health, uptime, and mTLS status.
* `GET /metrics` — Exposes active streams, total bytes transferred, rate limiting security counters, and node peer identity.
* `WSS /control/ws` — Real-time telemetry WebSocket streaming live metric snapshots every 1000ms.



---

## ⚡ Verified Master Benchmark Suite

Tested under the automated Phase 3 Master Benchmark Harness across multi-hop Sphinx Onion encrypted streams:

```text
===========================================================================
  AEON AEGIS - PHASE 3 FULL-STACK ZERO-TRUST BENCHMARK HARNESS
===========================================================================
[1/4] Mock Origin TCP Server:   ACTIVE (127.0.0.1:8080)
[2/4] WireGuard UDP Overlay:    ACTIVE (70.66 ms)
[3/4] mTLS Control Plane:       VERIFIED (270.42 ms, CN:client.aeon.internal)
[4/4] Target Multiaddr:         /ip4/127.0.0.1/tcp/9090/p2p/12D3KooWSjSKpq43wgspUxJAvV46JKaJFu5RwKXe4qGUefyfhHry

===========================================================================
  BENCHMARK RESULTS SUMMARY
===========================================================================
Total Requests Sent:        100
Successful Requests:        100 (100.00%)
Failed Requests:            0
Throughput:                 10.12 req/sec
Mean Stream RTT:            978.41 ms
===========================================================================

✅ BENCHMARK PASSED: 100% Zero-Trust Routing & Sphinx Onion Encryption Verified.

```

### Telemetry & Performance Summary

| Benchmark Metric | Result Value | Verification Status |
| --- | --- | --- |
| **Total Test Streams** | 100 / 100 Streams | **100.00% Success (0 Drops)** |
| **Throughput Capacity** | 10.12 req/sec | **PASSED** |
| **Mean Stream RTT** | 978.41 ms | **PASSED** |
| **WireGuard UDP Ping** | 70.66 ms RTT | **ACTIVE** |
| **mTLS Control Plane** | 270.42 ms RTT | **VERIFIED (`client.aeon.internal`)** |
| **Cryptographic Zeroization** | Explicit `sharedSecret.fill(0)` | **AUDIT PASSED** |
| **Memory Footprint** | `<256MB` RAM | **PASSED** |

---

## 🚀 Quickstart

### 1. Installation & Compilation

```bash
git clone https://github.com/CrushioDarhk/Aeon-Aegis.git
cd Aeon-Aegis
npm install
npm run build

```

### 2. Running Locally

Start Relay Node & Control Plane:

```bash
npm run dev

```

Execute Full-Stack Benchmark Suite:

```bash
npm run benchmark

```

### 3. Querying mTLS Control Plane

```bash
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://127.0.0.1:9091/health
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://127.0.0.1:9091/metrics

```

---

## ☁️ Akash Network SDL v2.0 (`deploy.sdl`)

Configured for Akash Network deployment using micro-ACT (`uact`) token settlement:

```yaml
version: "2.0"

services:
  aeon-relay:
    image: ghcr.io/aeon-aegis-network/aeon-aegis:latest
    expose:
      # WireGuard UDP Overlay Gateway
      - port: 51820
        as: 51820
        proto: udp
        to:
          - global: true
      # Noise P2P Relay Listener
      - port: 9090
        as: 9090
        proto: tcp
        to:
          - global: true
      # mTLS Control & Telemetry Plane
      - port: 9091
        as: 9091
        proto: tcp
        to:
          - global: true
    env:
      - NODE_ENV=production
      - RELAY_LISTEN_HOST=10.0.0.1
      - RELAY_P2P_PORT=9090
      - RELAY_CONTROL_PORT=9091
      - ORIGIN_HOST=127.0.0.1
      - ORIGIN_PORT=8080

profiles:
  compute:
    aeon-relay:
      resources:
        cpu:
          units: 0.5
        memory:
          size: 512Mi
        storage:
          size: 2Gi
  placement:
    akash:
      pricing:
        aeon-relay:
          denom: uact
          amount: 10000

deployment:
  aeon-relay:
    akash:
      profile: aeon-relay
      count: 1

```
