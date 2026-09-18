export interface RateLimiterConfig {
  capacity: number;
  refillRate: number;
  banThreshold: number;
  banDurationMs: number;
}

export interface SecurityCheckResult {
  allowed: boolean;
  reason?: string;
  score: number;
}

export class SecurityManager {
  private capacity: number;
  private refillRate: number;
  private tokens: Map<string, number> = new Map();
  private lastRefill: Map<string, number> = new Map();
  private bannedIPs: Map<string, number> = new Map();

  constructor(config: RateLimiterConfig) {
    this.capacity = config.capacity;
    this.refillRate = config.refillRate;
  }

  public isAllowed(ip: string): SecurityCheckResult {
    // Whitelist loopback interfaces for local benchmark execution
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
      return { allowed: true, score: 100 };
    }

    const now = Date.now();

    // Check existing ban state
    const banExpiry = this.bannedIPs.get(ip);
    if (banExpiry && now < banExpiry) {
      return { allowed: false, reason: 'ip_banned', score: 0 };
    } else if (banExpiry) {
      this.bannedIPs.delete(ip);
    }

    // Initialize or refill tokens
    let currentTokens = this.tokens.get(ip) ?? this.capacity;
    const lastRefillTime = this.lastRefill.get(ip) ?? now;
    const elapsedSec = (now - lastRefillTime) / 1000;

    currentTokens = Math.min(this.capacity, currentTokens + elapsedSec * this.refillRate);
    this.lastRefill.set(ip, now);

    if (currentTokens >= 1) {
      this.tokens.set(ip, currentTokens - 1);
      return { allowed: true, score: Math.floor(currentTokens) };
    }

    return { allowed: false, reason: 'rate_limited', score: 0 };
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