import net from 'node:net';

const PORT = parseInt(process.env.ORIGIN_PORT || '8080', 10);
const HOST = process.env.ORIGIN_HOST || '127.0.0.1';

/**
 * Aeon Aegis - Mock Target Origin TCP/HTTP Server
 * Listens on 127.0.0.1:8080 and responds to proxied zero-trust requests.
 */
const server = net.createServer((socket) => {
  socket.on('data', (data) => {
    const payload = data.toString();

    // Respond with HTTP 200 OK if request is HTTP-formatted
    if (payload.includes('HTTP/')) {
      const body = JSON.stringify({
        status: 'success',
        origin: 'Aeon Aegis Mock Target',
        timestamp: new Date().toISOString()
      });

      const response =
        'HTTP/1.1 200 OK\r\n' +
        'Content-Type: application/json\r\n' +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        'Connection: close\r\n\r\n' +
        body;

      socket.write(response);
      socket.end();
    } else {
      // Direct raw TCP payload echo back
      socket.write(data);
      socket.end();
    }
  });

  socket.on('error', () => {
    // Suppress unexpected client socket drops
  });
});

server.listen(PORT, HOST, () => {
  console.log(`========================================`);
  console.log(`  AEON AEGIS - MOCK ORIGIN ONLINE       `);
  console.log(`========================================`);
  console.log(`Listening on target: ${HOST}:${PORT}`);
});