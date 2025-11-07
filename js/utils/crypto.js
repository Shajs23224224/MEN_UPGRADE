/**
 * Cryptographic Utilities
 * Provides cryptographic functions for hashing, token generation, and encryption
 */

import { SecurityConfig } from '../config/security.js';
import { Logger } from './logger.js';

export class CryptoUtils {
  constructor() {
    this.logger = new Logger('CryptoUtils');
    
    // Check for required environment variables in production
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'your-256-bit-secret-change-in-production') {
        this.logger.error('JWT_SECRET is not set or is using default value');
        throw new Error('JWT_SECRET is not properly configured');
      }
    }
  }

  /**
   * Hash a password using bcrypt
   * @param {string} password - Plain text password
   * @returns {Promise<string>} - Hashed password
   */
  async hashPassword(password) {
    try {
      // In a real app, this would use bcrypt or Argon2
      // This is a simplified example using the Web Crypto API
      const encoder = new TextEncoder();
      const data = encoder.encode(password + SecurityConfig.JWT.SECRET);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      return `$2b$10$${hashHex.substring(0, 54)}`; // Simulate bcrypt format
    } catch (error) {
      this.logger.error('Password hashing failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify a password against a hash
   * @param {string} password - Plain text password
   * @param {string} hash - Hashed password
   * @returns {Promise<boolean>} - Whether the password matches the hash
   */
  async verifyPassword(password, hash) {
    try {
      // In a real app, this would use bcrypt or Argon2
      // This is a simplified example
      const hashedPassword = await this.hashPassword(password);
      return hashedPassword === hash;
    } catch (error) {
      this.logger.error('Password verification failed', { error: error.message });
      return false;
    }
  }

  /**
   * Generate a JWT token
   * @param {Object} payload - Token payload
   * @param {string} secret - Secret key for signing
   * @param {Object} options - Additional options
   * @returns {string} - JWT token
   */
  generateToken(payload, secret = SecurityConfig.JWT.SECRET, options = {}) {
    try {
      // In a real app, this would use jsonwebtoken or jose library
      // This is a simplified example
      const header = {
        alg: 'HS256',  // HMAC with SHA-256
        typ: 'JWT',
      };
      
      const encodedHeader = this._base64UrlEncode(JSON.stringify(header));
      const encodedPayload = this._base64UrlEncode(JSON.stringify({
        ...payload,
        iat: payload.iat || Math.floor(Date.now() / 1000),
        exp: payload.exp || Math.floor((Date.now() + 15 * 60 * 1000) / 1000), // 15 minutes
      }));
      
      // In a real app, this would use HMAC-SHA256 for signing
      const signature = this._hmacSha256(
        `${encodedHeader}.${encodedPayload}`,
        secret
      );
      
      return `${encodedHeader}.${encodedPayload}.${signature}`;
    } catch (error) {
      this.logger.error('Token generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify a JWT token
   * @param {string} token - JWT token to verify
   * @param {string} secret - Secret key for verification
   * @param {Object} options - Verification options
   * @returns {Promise<Object>} - Decoded token payload
   */
  async verifyToken(token, secret = SecurityConfig.JWT.SECRET, options = {}) {
    try {
      if (!token) {
        throw new Error('No token provided');
      }
      
      // In a real app, this would use jsonwebtoken or jose library
      // This is a simplified example
      const [encodedHeader, encodedPayload, signature] = token.split('.');
      
      if (!encodedHeader || !encodedPayload || !signature) {
        throw new Error('Invalid token format');
      }
      
      // Verify signature
      const expectedSignature = this._hmacSha256(
        `${encodedHeader}.${encodedPayload}`,
        secret
      );
      
      if (signature !== expectedSignature) {
        throw new Error('Invalid token signature');
      }
      
      // Decode payload
      const payload = JSON.parse(this._base64UrlDecode(encodedPayload));
      
      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token expired');
      }
      
      // Check audience if provided
      if (options.audience && payload.aud !== options.audience) {
        throw new Error('Invalid audience');
      }
      
      // Check issuer if provided
      if (options.issuer && payload.iss !== options.issuer) {
        throw new Error('Invalid issuer');
      }
      
      return payload;
    } catch (error) {
      this.logger.error('Token verification failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Generate a cryptographically secure random token
   * @param {number} length - Length of the token in bytes
   * @param {string} chars - Characters to use for the token
   * @returns {string} - Random token
   */
  generateRandomToken(length = 32, chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
    try {
      const randomValues = new Uint8Array(length);
      crypto.getRandomValues(randomValues);
      
      let result = '';
      for (let i = 0; i < length; i++) {
        result += chars[randomValues[i] % chars.length];
      }
      
      return result;
    } catch (error) {
      this.logger.error('Random token generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Generate a UUID v4
   * @returns {string} - UUID v4
   */
  generateUuid() {
    try {
      // In a real app, you might use the uuid package
      // This is a simplified example
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      });
    } catch (error) {
      this.logger.error('UUID generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Generate a TOTP secret
   * @param {Object} options - Options for TOTP generation
   * @returns {Object} - TOTP secret and URI
   */
  generateMfaSecret(options = {}) {
    try {
      const secret = this.generateRandomToken(20, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'); // Base32 alphabet
      
      const config = {
        name: options.name || 'MejoraMasculina',
        issuer: options.issuer || SecurityConfig.MFA.TOTP.ISSUER,
        algorithm: 'SHA1',
        digits: SecurityConfig.MFA.TOTP.DIGITS,
        period: SecurityConfig.MFA.TOTP.STEP,
        secret,
      };
      
      // Generate otpauth URI
      const params = new URLSearchParams({
        secret: config.secret,
        issuer: config.issuer,
        algorithm: config.algorithm,
        digits: config.digits,
        period: config.period,
      });
      
      const otpauthUrl = `otpauth://totp/${encodeURIComponent(config.issuer)}:${encodeURIComponent(options.name || '')}?${params.toString()}`;
      
      return {
        secret: config.secret,
        otpauth_url: otpauthUrl,
      };
    } catch (error) {
      this.logger.error('MFA secret generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Verify a TOTP code
   * @param {string} token - TOTP code to verify
   * @param {string} secret - TOTP secret
   * @param {Object} options - Verification options
   * @returns {boolean} - Whether the code is valid
   */
  verifyTotp(token, secret, options = {}) {
    try {
      if (!token || !secret) {
        return false;
      }
      
      const config = {
        digits: options.digits || SecurityConfig.MFA.TOTP.DIGITS,
        step: options.step || SecurityConfig.MFA.TOTP.STEP,
        window: options.window || SecurityConfig.MFA.TOTP.WINDOW,
      };
      
      // In a real app, this would use a TOTP library like speakeasy or otplib
      // This is a simplified example
      const expectedToken = this._generateTotp(secret, config);
      return token === expectedToken;
    } catch (error) {
      this.logger.error('TOTP verification failed', { error: error.message });
      return false;
    }
  }

  /**
   * Generate a hash using HMAC-SHA256
   * @private
   */
  _hmacSha256(message, secret) {
    // In a real app, this would use the Web Crypto API or a library
    // This is a simplified example
    const encoder = new TextEncoder();
    const key = encoder.encode(secret);
    const data = encoder.encode(message);
    
    // Simulate HMAC-SHA256
    const hash = Array.from(data)
      .map((byte, i) => byte ^ key[i % key.length])
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
      
    return hash.substring(0, 43); // Simulate base64url encoding
  }

  /**
   * Base64 URL encode a string
   * @private
   */
  _base64UrlEncode(str) {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * Base64 URL decode a string
   * @private
   */
  _base64UrlDecode(str) {
    const padding = '='.repeat((4 - (str.length % 4)) % 4);
    const base64 = (str + padding).replace(/\-/g, '+').replace(/_/g, '/');
    return decodeURIComponent(escape(atob(base64)));
  }

  /**
   * Generate a TOTP code (simplified)
   * @private
   */
  _generateTotp(secret, options = {}) {
    // In a real app, this would use a TOTP library
    // This is a simplified example
    const time = Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / (options.step || 30));
    
    // Generate a deterministic code based on the counter and secret
    let code = '';
    for (let i = 0; i < (options.digits || 6); i++) {
      const charCode = (counter + i + secret.charCodeAt(i % secret.length)) % 10;
      code += charCode.toString();
    }
    
    return code.substring(0, options.digits || 6);
  }
}

// Export singleton instance
export const cryptoUtils = new CryptoUtils();
