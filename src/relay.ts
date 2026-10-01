import net from 'node:net';
import https from 'node:https';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { multiaddr } from '@multiformats/multiaddr';
import type { Stream, Connection } from '@libp2p/interface';
import { SecurityManager } from './security/rateLimiter.js';
import { unwrapOnionLayer } from './security/onionRouter.js';

/**
 * ============================================================================
 * Aeon Aegis - Zero-Trust P2P Relay Node with Multi-Hop Onion Routing
 * ============================================================================
 */

// Configuration constants
export const RELAY_LISTEN_HOST = process.env.RELAY_LISTEN_HOST || '0.0.0.0';
export const RELAY_P2P_PORT = parseInt(process.env.RELAY_P2P_PORT || '9090', 10);
export const RELAY_CONTROL_PORT = parseInt(process.env.RELAY_CONTROL_PORT || '9091', 10);
export const ORIGIN_HOST = process.env.ORIGIN_HOST || '127.0.0.1';
export const ORIGIN_PORT = parseInt(process.env.ORIGIN_PORT || '8080', 10);
export const WG_PORT = parseInt(process.env.WG_PORT || '51820', 10);

// Protocol Definitions
export const AEON_RELAY_PROTOCOL = '/aeon-aegis/relay/1.0.0';
export const AEON_ONION_PROTOCOL = '/aeon-aegis/onion/1.0.0';

// X25519 Node Private & Public Keys for Sphinx Onion Decryption
const { privateKey: nodePrivKey, publicKey: nodePubKey } = crypto.generateKeyPairSync('x25519');
export const NODE_IDENTITY_KEY: crypto.KeyObject = nodePrivKey;
export const NODE_PUBLIC_KEY: crypto.KeyObject = nodePubKey;
export const NODE_PUBLIC_KEY_RAW: Buffer = (nodePubKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32);

// Global Security Manager Instance
export const security = new SecurityManager({
  capacity: parseInt(process.env.RATE_LIMIT_CAPACITY || '2000', 10),
  refillRate: parseInt(process.env.RATE_LIMIT_REFILL || '500', 10),
  banThreshold: -100,   // Headroom prior to triggering IP ban
  banDurationMs: 900000 // 15-minute ban duration
});

// Structured logger
export function logJSON(level: 'info' | 'warn' | 'error', event: string, data: Record<string, any> = {}) {
  const logEntry = {
    level,
    timestamp: new Date().toISOString(),
    event,
    ...data
  };
  process.stdout.write(JSON.stringify(logEntry) + '\n');
  return logEntry;
}

// Telemetry & Metrics State
export interface RelayMetrics {
  activeConnections: number;
  totalConnectionsHandled: number;
  totalStreamsProxied: number;
  totalOnionLayersUnwrapped: number;
  totalBytesIn: number;
  totalBytesOut: number;
  handshakeDurationsMs: number[];
  recentErrors: number;
  startTime: number;
}

export const metrics: RelayMetrics = {
  activeConnections: 0,
  totalConnectionsHandled: 0,
  totalStreamsProxied: 0,
  totalOnionLayersUnwrapped: 0,
  totalBytesIn: 0,
  totalBytesOut: 0,
  handshakeDurationsMs: [],
  recentErrors: 0,
  startTime: Date.now()
};

/**
 * Bounded Async Push Queue with max capacity to prevent memory leaks / exhaustion
 */
class AsyncPushQueue<T> implements AsyncIterable<T> {
  private queue: T[] = [];
  private resolvers: ((value: IteratorResult<T>) => void)[] = [];
  private done = false;
  private readonly maxQueueSize: number;

  constructor(maxQueueSize: number = 2048) {
    this.maxQueueSize = maxQueueSize;
  }

  push(value: T) {
    if (this.done) return;
    if (this.resolvers.length > 0) {
      const resolve = this.resolvers.shift()!;
      resolve({ value, done: false });
    } else {
      if (this.queue.length >= this.maxQueueSize) {
        this.queue.shift(); // Evict oldest chunk if receiver is blocked
      }
      this.queue.push(value);
    }
  }

  end() {
    if (this.done) return;
    this.done = true;
    this.queue = [];
    while (this.resolvers.length > 0) {
      const resolve = this.resolvers.shift()!;
      resolve({ value: undefined as any, done: true });
    }
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: (): Promise<IteratorResult<T>> => {
        if (this.queue.length > 0) {
          return Promise.resolve({ value: this.queue.shift()!, done: false });
        }
        if (this.done) {
          return Promise.resolve({ value: undefined as any, done: true });
        }
        return new Promise((resolve) => this.resolvers.push(resolve));
      }
    };
  }
}

/**
 * Proxy function: Strips client origin metadata and pipes decrypted payload
 * between libp2p stream and internal origin TCP server.
 */
export function proxyStreamToOrigin(
  stream: Stream,
  connection: Connection | undefined,
  handshakeDurationMs: number,
  initialPayload?: Uint8Array | null
): void {
  metrics.totalStreamsProxied++;
  const streamId = stream.id;

  logJSON('info', 'stream_proxy_initiated', {
    stream_id: streamId,
    active_connections: metrics.activeConnections,
    handshake_duration_ms: handshakeDurationMs,
    target: `${ORIGIN_HOST}:${ORIGIN_PORT}`,
    action: 'metadata_stripped'
  });

  const originSocket = net.createConnection({ host: ORIGIN_HOST, port: ORIGIN_PORT });
  const outboundQueue = new AsyncPushQueue<Uint8Array>(2048);
  let streamClosed = false;

  const cleanup = () => {
    if (streamClosed) return;
    streamClosed = true;
    outboundQueue.end();
    try {
      if (!originSocket.destroyed) {
        originSocket.destroy();
      }
    } catch {}
    try {
      (stream as any).close?.();
    } catch {}
  };

  originSocket.on('connect', () => {
    logJSON('info', 'origin_socket_connected', {
      stream_id: streamId,
      origin: `${ORIGIN_HOST}:${ORIGIN_PORT}`
    });

    // If an initial unwrapped payload exists (Sphinx Onion Exit), route it immediately
    if (initialPayload && initialPayload.length > 0) {
      metrics.totalBytesIn += initialPayload.byteLength;
      originSocket.write(initialPayload, (err) => {
        if (err) {
          logJSON('error', 'origin_initial_write_failed', { stream_id: streamId, error: err.message });
          cleanup();
        }
      });
    }
  });

  if (typeof (stream as any).sink === 'function') {
    (stream as any).sink(outboundQueue).catch(() => cleanup());
  }

  // Consume incoming P2P stream chunks if no static initialPayload was provided
  if (!initialPayload) {
    (async () => {
      try {
        const source = (stream as any).source || stream;
        for await (const chunk of source) {
          const rawData =
            chunk instanceof Uint8Array
              ? chunk
              : chunk && typeof chunk.subarray === 'function'
              ? chunk.subarray()
              : new Uint8Array(chunk);

          const bytesCount = rawData.byteLength;
          metrics.totalBytesIn += bytesCount;

          logJSON('info', 'payload_routed_to_origin', {
            stream_id: streamId,
            bytes_transferred: bytesCount,
            active_connections: metrics.activeConnections,
            handshake_duration_ms: handshakeDurationMs
          });

          if (!originSocket.destroyed) {
            originSocket.write(rawData, (err) => {
              if (err) cleanup();
            });
          }
        }
      } catch (err: any) {
        metrics.recentErrors++;
        logJSON('error', 'origin_write_failed', {
          stream_id: streamId,
          error: err?.message
        });
        cleanup();
      }
    })();
  }

  originSocket.on('data', (data: Buffer) => {
    try {
      const bytesCount = data.byteLength;
      metrics.totalBytesOut += bytesCount;

      logJSON('info', 'payload_routed_to_client', {
        stream_id: streamId,
        bytes_transferred: bytesCount,
        active_connections: metrics.activeConnections
      });

      const chunk = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      if (typeof (stream as any).send === 'function') {
        (stream as any).send(chunk);
      }
      outboundQueue.push(chunk);
    } catch (err: any) {
      metrics.recentErrors++;
      logJSON('error', 'stream_send_failed', {
        stream_id: streamId,
        error: err?.message
      });
      cleanup();
    }
  });

  originSocket.on('end', () => {
    logJSON('info', 'origin_socket_end', { stream_id: streamId });
    outboundQueue.end();
    try {
      (stream as any).close?.();
    } catch {}
    cleanup();
  });

  originSocket.on('error', (err: any) => {
    metrics.recentErrors++;
    logJSON('error', 'origin_socket_error', {
      stream_id: streamId,
      error: err.message
    });

    if (!streamClosed) {
      const errorPayload = Buffer.from(
        'HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\nAeonAegis_OriginUnreachable'
      );
      const errChunk = new Uint8Array(errorPayload.buffer, errorPayload.byteOffset, errorPayload.byteLength);
      if (typeof (stream as any).send === 'function') {
        (stream as any).send(errChunk);
      }
      outboundQueue.push(errChunk);
    }
    cleanup();
  });

  originSocket.on('close', () => { cleanup(); });
  stream.addEventListener('close', () => { cleanup(); });
}

/**
 * Initializes and starts the libp2p Relay Node with Security Enforcement & Multi-Hop Onion Handling.
 */
export async function startRelayNode() {
  const node = await createLibp2p({
    addresses: {
      listen: [`/ip4/${RELAY_LISTEN_HOST}/tcp/${RELAY_P2P_PORT}`]
    },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [
      yamux({
        maxInboundStreams: 4096,
        maxOutboundStreams: 4096
      })
    ]
  });

  const connectionHandshakeStart = new Map<string, number>();

  node.addEventListener('connection:open', (event) => {
    const conn = event.detail;
    const now = Date.now();
    metrics.activeConnections++;
    metrics.totalConnectionsHandled++;

    const startTime = connectionHandshakeStart.get(conn.id) || now;
    const handshakeDurationMs = Math.max(1, now - startTime);
    metrics.handshakeDurationsMs.push(handshakeDurationMs);

    if (metrics.handshakeDurationsMs.length > 500) {
      metrics.handshakeDurationsMs.shift();
    }

    logJSON('info', 'noise_connection_opened', {
      connection_id: conn.id,
      active_connections: metrics.activeConnections,
      handshake_duration_ms: handshakeDurationMs,
      total_connections: metrics.totalConnectionsHandled
    });
  });

  node.addEventListener('connection:close', (event) => {
    const conn = event.detail;
    metrics.activeConnections = Math.max(0, metrics.activeConnections - 1);
    connectionHandshakeStart.delete(conn.id);

    logJSON('info', 'connection_closed', {
      connection_id: conn.id,
      active_connections: metrics.activeConnections
    });
  });

  // Standard Direct P2P Relay Handler
  node.handle(AEON_RELAY_PROTOCOL, (data: any) => {
    const stream: Stream = data.stream || data;
    const connection: Connection | undefined = data.connection;

    let remoteIP = '127.0.0.1';
    try {
      if (connection && connection.remoteAddr) {
        const parts = connection.remoteAddr.toString().split('/');
        const ipIdx = parts.findIndex((p: string) => p === 'ip4' || p === 'ip6');
        if (ipIdx !== -1 && parts[ipIdx + 1]) {
          remoteIP = parts[ipIdx + 1];
        }
      }
    } catch {
      remoteIP = '127.0.0.1';
    }

    const check = security.isAllowed(remoteIP);
    if (!check.allowed) {
      logJSON('warn', 'security_stream_blocked', {
        stream_id: stream.id,
        remote_ip: remoteIP,
        reason: check.reason,
        reputation_score: check.score
      });
      try {
        (stream as any).reset?.();
      } catch {}
      return;
    }

    const durations = metrics.handshakeDurationsMs;
    const latestHandshake = durations.length > 0 ? durations[durations.length - 1] : 0;
    proxyStreamToOrigin(stream, connection, latestHandshake);
  }, {
    maxInboundStreams: 4096,
    maxOutboundStreams: 4096
  });

  // Multi-Hop Sphinx Onion Protocol Handler
  node.handle(AEON_ONION_PROTOCOL, async (data: any) => {
    const stream: Stream = data.stream || data;
    const connection: Connection | undefined = data.connection;

    try {
      const chunks: Uint8Array[] = [];
      const source = (stream as any).source || stream;

      for await (const chunk of source) {
        chunks.push(chunk instanceof Uint8Array ? chunk : chunk.subarray());
        break; // Read initial encrypted onion frame
      }

      const rawOnionFrame = Buffer.concat(chunks);
      
      // Peel single layer using node's identity private key
      const unwrapped = unwrapOnionLayer(NODE_IDENTITY_KEY, rawOnionFrame);
      metrics.totalOnionLayersUnwrapped++;

      if (unwrapped.isExit) {
        logJSON('info', 'onion_circuit_exit_reached', {
          action: 'proxy_to_validator',
          destination: unwrapped.nextHopAddress
        });
        
        // Final Egress Node: Proxy inner decrypted payload directly to origin
        proxyStreamToOrigin(stream, connection, 0, unwrapped.innerPayload);
      } else {
        logJSON('info', 'onion_circuit_forwarding', {
          action: 'relay_to_next_hop',
          next_hop: unwrapped.nextHopAddress
        });

        // Forward inner encrypted payload to next hop
        const nextHopAddr = multiaddr(unwrapped.nextHopAddress);
        const outboundStream = await node.dialProtocol(nextHopAddr as any, AEON_ONION_PROTOCOL);

        if (typeof (outboundStream as any).sink === 'function') {
          await (outboundStream as any).sink(
            (async function* () {
              yield unwrapped.innerPayload;
            })()
          );
        } else if (typeof (outboundStream as any).send === 'function') {
          await (outboundStream as any).send(unwrapped.innerPayload);
        }
      }
    } catch (err: any) {
      metrics.recentErrors++;
      logJSON('error', 'onion_layer_unwrap_failed', { error: err?.message });
      try {
        (stream as any).reset?.();
      } catch {}
    }
  }, {
    maxInboundStreams: 4096,
    maxOutboundStreams: 4096
  });

  return node;
}

/**
 * Starts WireGuard UDP overlay ping responder
 */
export function startWireGuardOverlay(port: number, host: string): dgram.Socket {
  const socket = dgram.createSocket('udp4');
  socket.on('message', (msg, rinfo) => {
    socket.send(msg, rinfo.port, rinfo.address, (err) => {
      if (err) logJSON('warn', 'wireguard_udp_send_error', { error: err.message });
    });
  });
  socket.on('error', (err) => {
    logJSON('warn', 'wireguard_udp_error', { error: err.message });
  });
  socket.bind(port, host, () => {
    logJSON('info', 'wireguard_overlay_online', { port, host });
  });
  return socket;
}

/**
 * Control plane for health checks, security metrics, and telemetry protected by strict mTLS.
 */
export function startControlPlane(libp2pNode: any) {
  const app = express();
  app.use(express.json());

  // Load PKI Certificates
  const certsDir = path.join(process.cwd(), 'certs');
  const ca = fs.readFileSync(path.join(certsDir, 'ca.crt'));
  const cert = fs.readFileSync(path.join(certsDir, 'server.crt'));
  const key = fs.readFileSync(path.join(certsDir, 'server.key'));

  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      service: 'aeon-aegis-relay',
      mtls_status: 'enforced',
      uptime_seconds: Math.floor((Date.now() - metrics.startTime) / 1000),
      timestamp: new Date().toISOString()
    });
  });

  app.get('/metrics', (req, res) => {
    const clientCert = (req.socket as any).getPeerCertificate?.();
    const clientCN = clientCert?.subject?.CN || 'unknown';

    const durations = metrics.handshakeDurationsMs;
    const avgHandshake = durations.length > 0
      ? (durations.reduce((a, b) => a + b, 0) / durations.length).toFixed(2)
      : '0.00';

    res.json({
      authenticated_client_cn: clientCN,
      active_connections: metrics.activeConnections,
      total_connections: metrics.totalConnectionsHandled,
      total_streams_proxied: metrics.totalStreamsProxied,
      total_onion_layers_unwrapped: metrics.totalOnionLayersUnwrapped,
      total_bytes_in: metrics.totalBytesIn,
      total_bytes_out: metrics.totalBytesOut,
      avg_noise_handshake_ms: parseFloat(avgHandshake),
      security: security.getMetrics(),
      peer_id: libp2pNode.peerId.toString(),
      onion_public_key: NODE_PUBLIC_KEY_RAW.toString('hex'),
      listen_addresses: libp2pNode.getMultiaddrs().map((a: any) => a.toString())
    });
  });

  // Instantiate HTTPS Server with mandatory Mutual TLS
  const server = https.createServer(
    {
      key,
      cert,
      ca,
      requestCert: true,          // Require client certificate
      rejectUnauthorized: true     // Drop unauthenticated TLS connections
    },
    app
  );

  const wss = new WebSocketServer({ server, path: '/control/ws' });

  wss.on('connection', (ws: WebSocket, req) => {
    const clientCert = (req.socket as any).getPeerCertificate?.();
    const clientCN = clientCert?.subject?.CN || 'authenticated_client';

    logJSON('info', 'control_ws_client_connected', { client_cn: clientCN });

    ws.send(JSON.stringify({
      type: 'SNAPSHOT',
      authenticated_client: clientCN,
      metrics,
      security: security.getMetrics(),
      timestamp: new Date().toISOString()
    }));

    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'METRICS_UPDATE',
          activeConnections: metrics.activeConnections,
          bytesIn: metrics.totalBytesIn,
          bytesOut: metrics.totalBytesOut,
          security: security.getMetrics(),
          timestamp: new Date().toISOString()
        }));
      }
    }, 1000);

    ws.on('close', () => {
      clearInterval(interval);
      logJSON('info', 'control_ws_client_disconnected', { client_cn: clientCN });
    });
  });

  server.listen(RELAY_CONTROL_PORT, RELAY_LISTEN_HOST, () => {
    logJSON('info', 'control_plane_started', {
      port: RELAY_CONTROL_PORT,
      bind_host: RELAY_LISTEN_HOST,
      mtls: true,
      health_endpoint: `https://${RELAY_LISTEN_HOST}:${RELAY_CONTROL_PORT}/health`,
      metrics_endpoint: `https://${RELAY_LISTEN_HOST}:${RELAY_CONTROL_PORT}/metrics`,
      ws_endpoint: `wss://${RELAY_LISTEN_HOST}:${RELAY_CONTROL_PORT}/control/ws`
    });
  });

  return server;
}

/**
 * Main execution entry point
 */
async function main() {
  logJSON('info', 'relay_node_initializing', {
    listen_host: RELAY_LISTEN_HOST,
    p2p_port: RELAY_P2P_PORT,
    control_port: RELAY_CONTROL_PORT,
    target_origin: `${ORIGIN_HOST}:${ORIGIN_PORT}`
  });

  const node = await startRelayNode();
  await node.start();

  const listenAddrs = node.getMultiaddrs().map(a => a.toString());
  logJSON('info', 'relay_node_online', {
    peer_id: node.peerId.toString(),
    onion_public_key: NODE_PUBLIC_KEY_RAW.toString('hex'),
    listen_addresses: listenAddrs,
    encryption: 'Noise + Sphinx Onion',
    protocols: [AEON_RELAY_PROTOCOL, AEON_ONION_PROTOCOL]
  });

  const controlServer = startControlPlane(node);
  const wgSocket = startWireGuardOverlay(WG_PORT, RELAY_LISTEN_HOST);

  const shutdown = async () => {
    logJSON('info', 'relay_node_shutting_down');
    try {
      wgSocket.close();
      controlServer.close();
      await node.stop();
    } catch (err: any) {
      logJSON('error', 'shutdown_error', { error: err?.message });
    }
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (process.argv[1] && (process.argv[1].endsWith('relay.ts') || process.argv[1].endsWith('relay.js'))) {
  main().catch((err) => {
    logJSON('error', 'relay_node_fatal_error', {
      error: err?.message,
      stack: err?.stack
    });
    process.exit(1);
  });
}