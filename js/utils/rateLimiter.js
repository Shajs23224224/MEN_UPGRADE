/**
 * Rate Limiter Utility
 * Implements token bucket algorithm for rate limiting
 */

import { Logger } from './logger.js';

/**
 * RateLimiter class for handling rate limiting
 */
export class RateLimiter {
  /**
   * Create a new RateLimiter instance
   * @param {Object} options - Configuration options
   * @param {number} options.windowMs - Time window in milliseconds
   * @param {number} options.maxAttempts - Maximum number of attempts allowed in the time window
   * @param {number} [options.delayAfter] - Number of attempts after which to start delaying
   * @param {number} [options.delayMs] - Delay in milliseconds to apply after delayAfter is reached
   */
  constructor({
    windowMs = 15 * 60 * 1000, // 15 minutes
    maxAttempts = 5,
    delayAfter = 3,
    delayMs = 1000,
  } = {}) {
    this.windowMs = windowMs;
    this.maxAttempts = maxAttempts;
    this.delayAfter = delayAfter;
    this.delayMs = delayMs;
    this.store = new Map();
    this.cleanupInterval = setInterval(() => this._cleanup(), this.windowMs);
    this.logger = new Logger('RateLimiter');
  }

  /**
   * Check if a request is allowed
   * @param {string} key - Unique key to identify the client (e.g., IP address)
   * @returns {Promise<boolean>} - Whether the request is allowed
   */
  async check(key) {
    try {
      if (!key) {
        throw new Error('Rate limiter key is required');
      }

      const now = Date.now();
      const entry = this.store.get(key) || this._createNewEntry(now);

      // Check if the window has expired
      if (now - entry.firstAttemptAt > this.windowMs) {
        // Reset the entry if the window has expired
        this.store.set(key, this._createNewEntry(now));
        return true;
      }

      // Increment the attempt count
      entry.attempts += 1;
      entry.lastAttemptAt = now;
      this.store.set(key, entry);

      // Check if we've exceeded max attempts
      if (entry.attempts > this.maxAttempts) {
        this.logger.warn(`Rate limit exceeded for key: ${key}`, {
          attempts: entry.attempts,
          maxAttempts: this.maxAttempts,
        });
        return false;
      }

      // Apply delay if we're over the delayAfter threshold
      if (this.delayAfter && entry.attempts > this.delayAfter) {
        const delay = this.delayMs * (entry.attempts - this.delayAfter);
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      return true;
    } catch (error) {
      this.logger.error('Rate limiter check failed', { error: error.message });
      // Fail open in case of errors to avoid blocking legitimate requests
      return true;
    }
  }

  /**
   * Get time left until the rate limit resets
   * @param {string} key - Client key
   * @returns {number} - Time left in milliseconds
   */
  getTimeLeft(key) {
    const entry = this.store.get(key);
    if (!entry) return 0;

    const timeElapsed = Date.now() - entry.firstAttemptAt;
    return Math.max(0, this.windowMs - timeElapsed);
  }

  /**
   * Reset the rate limit for a specific key
   * @param {string} key - Client key to reset
   */
  resetKey(key) {
    this.store.delete(key);
  }

  /**
   * Clean up expired entries
   * @private
   */
  _cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now - entry.firstAttemptAt > this.windowMs) {
        this.store.delete(key);
      }
    }
  }

  /**
   * Create a new rate limit entry
   * @param {number} timestamp - Current timestamp
   * @returns {Object} - New rate limit entry
   * @private
   */
  _createNewEntry(timestamp) {
    return {
      attempts: 0,
      firstAttemptAt: timestamp,
      lastAttemptAt: timestamp,
    };
  }

  /**
   * Clean up resources
   */
  close() {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

// Export a singleton instance
export const rateLimiter = new RateLimiter();
