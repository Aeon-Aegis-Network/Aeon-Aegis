# ============================================================================
# Stage 1: Build & Compilation Stage
# ============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies for native modules
RUN apk add --no-cache python3 make g++

# Install dependencies (including devDependencies for TypeScript)
COPY package.json package-lock.json ./
RUN npm ci

# Copy TypeScript configuration, source code, and tests
COPY tsconfig.json ./
COPY src/ ./src/
COPY tests/ ./tests/

# Compile TypeScript to /app/dist
RUN npm run build

# Prune development dependencies for minimal footprint
RUN npm prune --omit=dev

# ============================================================================
# Stage 2: Minimal Zero-Trust Runtime Stage
# ============================================================================
FROM node:20-alpine AS runner

WORKDIR /app

# Install WireGuard user-space management utilities & iptables routing
RUN apk add --no-cache wireguard-tools iptables bash

# Environment Configuration
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=192"
ENV RELAY_LISTEN_HOST=10.0.0.1
ENV RELAY_P2P_PORT=9090
ENV RELAY_CONTROL_PORT=9091
ENV ORIGIN_HOST=127.0.0.1
ENV ORIGIN_PORT=8080

# Explicit WireGuard Overlay Paths
ENV WG_CONFIG_DIR=/app/config/wireguard
ENV WG_CONFIG_PATH=/app/config/wireguard/wg0.conf

# Copy runtime node_modules, compiled binaries, and configuration tree
COPY --chown=node:node --from=builder /app/package.json ./
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist

# Copy whole config directory (resolves to /app/config/wireguard/ inside container)
COPY --chown=node:node config/ ./config/

# Ensure strict read/write permissions on WireGuard keys (required by wg-quick)
RUN chmod 700 /app/config/wireguard && \
    chmod 600 /app/config/wireguard/* 2>/dev/null || true

# Expose WireGuard UDP overlay, Noise TCP relay, and mTLS control ports
EXPOSE 51820/udp 9090/tcp 9091/tcp

# Telemetry health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "import('http').then(h => h.get('http://127.0.0.1:9091/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1)))"

# Start relay node
CMD ["node", "dist/src/relay.js"]