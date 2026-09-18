import http from 'node:http';
import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { multiaddr } from '@multiformats/multiaddr';

/**
 * ============================================================================
 * Aeon Aegis - Asynchronous Load Testing & Benchmark Harness
 * ============================================================================
 * Measures:
 * 1. Average Noise Handshake Latency (ms)
 * 2. Mean Round-Trip Time / RTT (ms)
 * 3. Concurrent Request & Stream Capacity (100 concurrent requests)
 * 4. Success vs Failure Rate (%)
 * 5. Packet Routing Overhead & Throughput (req/sec)
 */

const RELAY_HOST = process.env.RELAY_HOST || '127.0.0.1';
const RELAY_PORT = parseInt(process.env.RELAY_P2P_PORT || '9090', 10);
const CONTROL_PORT = parseInt(process.env.RELAY_CONTROL_PORT || '9091', 10);
const CONCURRENCY = parseInt(process.env.CONCURRENCY || '100', 10);
const PROTOCOL = '/aeon-aegis/relay/1.0.0';
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '15000', 10);

interface RequestMetric {
  id: number;
  success: boolean;
  handshakeTimeMs: number;
  rttMs: number;
  error?: string;
  responsePayload?: string;
}

// Fetch relay peer ID from control plane endpoint if available
async function getRelayTargetMultiaddr(): Promise<string> {
  return new Promise((resolve) => {
    const req = http.get(`http://${RELAY_HOST}:${CONTROL_PORT}/metrics`, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.peer_id) {
            resolve(`/ip4/${RELAY_HOST}/tcp/${RELAY_PORT}/p2p/${parsed.peer_id}`);
            return;
          }
        } catch {
          // Fallback
        }
        resolve(`/ip4/${RELAY_HOST}/tcp/${RELAY_PORT}`);
      });
    });

    req.on('error', () => {
      resolve(`/ip4/${RELAY_HOST}/tcp/${RELAY_PORT}`);
    });

    req.setTimeout(2000, () => {
      req.destroy();
      resolve(`/ip4/${RELAY_HOST}/tcp/${RELAY_PORT}`);
    });
  });
}

function calculatePercentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

async function runBenchmark() {
  console.log('='.repeat(70));
  console.log('  AEON AEGIS - ZERO-TRUST P2P RELAY BENCHMARK HARNESS');
  console.log('='.repeat(70));
  console.log(`Target Relay:       ${RELAY_HOST}:${RELAY_PORT}`);
  console.log(`Concurrent Load:    ${CONCURRENCY} concurrent requests`);
  console.log(`Protocol:           ${PROTOCOL} (Mandatory Noise TCP)`);
  console.log('Resolving relay multiaddr...');

  const targetMultiaddrStr = await getRelayTargetMultiaddr();
  console.log(`Dialing Multiaddr:  ${targetMultiaddrStr}\n`);
  const targetAddr = multiaddr(targetMultiaddrStr);

  // Initialize benchmark client node
  console.log('Initializing benchmark client node...');
  const clientNode = await createLibp2p({
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()]
  });
  await clientNode.start();

  console.log('Initiating Noise protocol handshake over TCP...');
  const tHandshakeStart = performance.now();
  const connection = await clientNode.dial(targetAddr as any);
  const handshakeTimeMs = performance.now() - tHandshakeStart;
  console.log(`Noise protocol encryption handshake completed: ${handshakeTimeMs.toFixed(2)} ms`);
  console.log(`Remote Peer ID:     ${connection.remotePeer.toString()}`);
  console.log(`Firing ${CONCURRENCY} concurrent zero-trust proxied requests...\n`);

  const benchmarkStart = performance.now();
  const tasks: Promise<RequestMetric>[] = [];

  for (let i = 1; i <= CONCURRENCY; i++) {
    const requestId = i;
    tasks.push((async (): Promise<RequestMetric> => {
      let stream: any = null;
      let tReqStart = performance.now();

      try {
        // Open stream via dialProtocol
        stream = await clientNode.dialProtocol(targetAddr as any, PROTOCOL, { maxOutboundStreams: 1024 });
        tReqStart = performance.now();

        // HTTP request payload to protected origin
        const requestPayload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n';

        // Write payload to stream
        if (typeof stream.send === 'function') {
          stream.send(new TextEncoder().encode(requestPayload));
        } else if (typeof stream.sink === 'function') {
          stream.sink([new TextEncoder().encode(requestPayload)]);
        }

        // Actively read all response chunks from the stream
        const readResponse = async (): Promise<string> => {
          let responseData = '';
          const source = stream.source || stream;
          for await (const chunk of source) {
            responseData += new TextDecoder().decode(chunk instanceof Uint8Array ? chunk : chunk.subarray());
            if (responseData.includes('HTTP/1.1 200 OK') || responseData.includes('status')) {
              break;
            }
          }
          return responseData;
        };

        const timeoutPromise = new Promise<never>((_, reject) => {
          const t = setTimeout(() => reject(new Error(`Timeout after ${TIMEOUT_MS}ms`)), TIMEOUT_MS);
          if (typeof t.unref === 'function') t.unref();
        });

        const responseData = await Promise.race([readResponse(), timeoutPromise]);
        const rtt = performance.now() - tReqStart;

        // Record response time upon receiving response bytes and close stream immediately
        try {
          await stream.close();
        } catch {}

        const isValid = responseData.includes('HTTP/1.1 200 OK') || responseData.includes('status') || responseData.includes('protected');

        return {
          id: requestId,
          success: isValid,
          handshakeTimeMs,
          rttMs: rtt,
          responsePayload: responseData.trim()
        };
      } catch (err: any) {
        const rtt = performance.now() - tReqStart;
        return {
          id: requestId,
          success: false,
          handshakeTimeMs,
          rttMs: rtt,
          error: err?.message || 'Unknown error'
        };
      } finally {
        if (stream) {
          try {
            await stream.close();
          } catch {}
        }
      }
    })());
  }

  const results = await Promise.all(tasks);
  const benchmarkTotalDurationMs = performance.now() - benchmarkStart;

  try {
    await connection.close();
  } catch {}
  try {
    await clientNode.stop();
  } catch {}

  // Aggregation & Statistics
  const successfulResults = results.filter(r => r.success);
  const failedResults = results.filter(r => !r.success);

  const successCount = successfulResults.length;
  const failureCount = failedResults.length;
  const successRate = ((successCount / CONCURRENCY) * 100).toFixed(2);
  const failureRate = ((failureCount / CONCURRENCY) * 100).toFixed(2);

  const rttTimes = successfulResults.map(r => r.rttMs);
  const avgRtt = rttTimes.length > 0
    ? (rttTimes.reduce((a, b) => a + b, 0) / rttTimes.length).toFixed(2)
    : '0.00';
  const minRtt = rttTimes.length > 0 ? Math.min(...rttTimes).toFixed(2) : '0.00';
  const maxRtt = rttTimes.length > 0 ? Math.max(...rttTimes).toFixed(2) : '0.00';
  const p95Rtt = calculatePercentile(rttTimes, 95).toFixed(2);
  const p99Rtt = calculatePercentile(rttTimes, 99).toFixed(2);

  const throughput = ((successCount / benchmarkTotalDurationMs) * 1000).toFixed(2);

  console.log('='.repeat(70));
  console.log('  BENCHMARK RESULTS SUMMARY');
  console.log('='.repeat(70));
  console.log(`Total Requests:             ${CONCURRENCY}`);
  console.log(`Successful Requests:        ${successCount} (${successRate}%)`);
  console.log(`Failed Requests:            ${failureCount} (${failureRate}%)`);
  console.log(`Total Benchmark Duration:   ${benchmarkTotalDurationMs.toFixed(2)} ms`);
  console.log(`Throughput:                 ${throughput} req/sec`);
  console.log('-'.repeat(70));
  console.log('NOISE HANDSHAKE LATENCY:');
  console.log(`  Noise Handshake Time:     ${handshakeTimeMs.toFixed(2)} ms`);
  console.log('-'.repeat(70));
  console.log('ROUND TRIP TIME (RTT):');
  console.log(`  Mean RTT:                 ${avgRtt} ms`);
  console.log(`  Min / Max:                ${minRtt} ms / ${maxRtt} ms`);
  console.log(`  P95 / P99:                ${p95Rtt} ms / ${p99Rtt} ms`);
  console.log('='.repeat(70));

  if (failedResults.length > 0) {
    console.log('\nFailure Samples:');
    failedResults.slice(0, 5).forEach(f => {
      console.log(`  Request #${f.id}: ${f.error}`);
    });
  }

  // Structured JSON output for automated reporting
  const structuredReport = {
    benchmark: 'aeon-aegis-noise-relay',
    concurrency: CONCURRENCY,
    success_rate_pct: parseFloat(successRate),
    failure_rate_pct: parseFloat(failureRate),
    noise_handshake_ms: parseFloat(handshakeTimeMs.toFixed(2)),
    mean_rtt_ms: parseFloat(avgRtt),
    min_rtt_ms: parseFloat(minRtt),
    max_rtt_ms: parseFloat(maxRtt),
    p95_rtt_ms: parseFloat(p95Rtt),
    p99_rtt_ms: parseFloat(p99Rtt),
    throughput_req_sec: parseFloat(throughput),
    total_duration_ms: parseFloat(benchmarkTotalDurationMs.toFixed(2))
  };

  console.log('\nSTRUCTURED JSON REPORT:');
  console.log(JSON.stringify(structuredReport, null, 2));

  if (successCount === 0 || parseFloat(failureRate) > 5) {
    console.error('\nBenchmark failed: Error rate threshold exceeded.');
    process.exit(1);
  } else {
    console.log('\nBenchmark PASSED successfully (100% Zero-Trust Encrypted Routing).');
    process.exit(0);
  }
}

runBenchmark().catch((err) => {
  console.error('Benchmark execution error:', err);
  process.exit(1);
});