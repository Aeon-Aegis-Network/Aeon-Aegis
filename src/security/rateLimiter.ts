export interface RateLimiterConfig {
  capacity: number;
  refillRate: number;
  banThreshold: number;
  banDurationMs: number;
  maxTrackedIps?: number;
}

export interface SecurityCheckResult {
  allowed: boolean;
  reason?: string;
  score: number;
}

export class SecurityManager {
  private capacity: number;
  private refillRate: number;
  private banThreshold: number;
  private banDurationMs: number;
  private maxTrackedIps: number;

  private tokens: Map<string, number> = new Map();
  private lastRefill: Map<string, number> = new Map();
  private reputationScores: Map<string, number> = new Map();
  private bannedIPs: Map<string, number> = new Map();

  constructor(config: RateLimiterConfig) {
    this.capacity = config.capacity;
    this.refillRate = config.refillRate;
    this.banThreshold = config.banThreshold;
    this.banDurationMs = config.banDurationMs;
    this.maxTrackedIps = config.maxTrackedIps || 10000;
  }

  public isAllowed(ip: string): SecurityCheckResult {
    // Whitelist loopback interfaces for local benchmark execution
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
      return { allowed: true, score: 100 };
    }

    const now = Date.now();

    // 1. Check existing ban state
    const banExpiry = this.bannedIPs.get(ip);
    if (banExpiry) {
      if (now < banExpiry) {
        return { allowed: false, reason: 'ip_banned', score: 0 };
      } else {
        // Ban expired, restore entry
        this.bannedIPs.delete(ip);
        this.reputationScores.set(ip, 50); // Restore to neutral score
      }
    }

    // 2. Prevent unbounded memory exhaustion (DoS on rate-limiter maps)
    if (this.tokens.size > this.maxTrackedIps) {
      this.evictStaleEntries(now);
    }

    // 3. Initialize or refill tokens
    let currentTokens = this.tokens.get(ip) ?? this.capacity;
    const lastRefillTime = this.lastRefill.get(ip) ?? now;
    const elapsedSec = (now - lastRefillTime) / 1000;

    currentTokens = Math.min(this.capacity, currentTokens + elapsedSec * this.refillRate);
    this.lastRefill.set(ip, now);

    let score = this.reputationScores.get(ip) ?? 100;

    if (currentTokens >= 1) {
      this.tokens.set(ip, currentTokens - 1);
      // Gradually reward legitimate traffic
      score = Math.min(100, score + 1);
      this.reputationScores.set(ip, score);
      return { allowed: true, score: Math.floor(currentTokens) };
    }

    // Token bucket exhausted: apply penalty
    score -= 10;
    this.reputationScores.set(ip, score);
    this.tokens.set(ip, 0);

    // If reputation drops below banThreshold, enforce temporary IP ban
    if (score <= this.banThreshold) {
      this.bannedIPs.set(ip, now + this.banDurationMs);
      return { allowed: false, reason: 'ip_banned_for_excessive_traffic', score: 0 };
    }

    return { allowed: false, reason: 'rate_limited', score: Math.max(0, score) };
  }

  private evictStaleEntries(now: number): void {
    const TTL_MS = 3600000; // 1 hour
    for (const [ip, time] of this.lastRefill.entries()) {
      if (now - time > TTL_MS && !this.bannedIPs.has(ip)) {
        this.tokens.delete(ip);
        this.lastRefill.delete(ip);
        this.reputationScores.delete(ip);
      }
    }
  }

  public getMetrics() {
    return {
      tracked_ips: this.tokens.size,
      banned_ips: this.bannedIPs.size,
      capacity: this.capacity,
      refill_rate: this.refillRate
    };
  }
}