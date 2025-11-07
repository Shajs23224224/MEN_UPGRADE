/**
 * Security Configuration Module
 * Implements security best practices and configurations
 */

export const SecurityConfig = {
  // JWT Configuration
  JWT: {
    SECRET: process.env.JWT_SECRET || 'your-256-bit-secret-change-in-production',
    ALGORITHM: 'HS256', // Using HMAC-SHA256
    ACCESS_TOKEN_EXPIRY: '15m',
    REFRESH_TOKEN_EXPIRY: '7d',
    ISSUER: 'mejora-masculina',
    AUDIENCE: 'mejora-masculina-web',
  },
  
  // Password Policy
  PASSWORD_POLICY: {
    MIN_LENGTH: 12,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SYMBOLS: true,
    MAX_AGE_DAYS: 90, // Password expiration in days
    HISTORY: 5, // Remember last 5 passwords
  },
  
  // Rate Limiting
  RATE_LIMIT: {
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_ATTEMPTS: 5, // Max attempts per window
    DELAY_AFTER: 3, // Start delaying after 3 attempts
    DELAY_MS: 1000, // Delay each request by 1 second
  },
  
  // CORS Configuration
  CORS: {
    ALLOWED_ORIGINS: [
      'https://mejora-masculina.com',
      'https://www.mejora-masculina.com',
      'http://localhost:3000',
    ],
    ALLOWED_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    ALLOWED_HEADERS: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-CSRF-Token',
    ],
  },
  
  // Security Headers
  HEADERS: {
    XSS_PROTECTION: '1; mode=block',
    X_FRAME_OPTIONS: 'DENY',
    X_CONTENT_TYPE_OPTIONS: 'nosniff',
    REFERRER_POLICY: 'strict-origin-when-cross-origin',
    PERMISSIONS_POLICY: [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
    ].join(', '),
    CONTENT_SECURITY_POLICY: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
      ],
      imgSrc: [
        "'self'",
        'data:',
        'blob:',
        'https://*.google-analytics.com',
        'https://*.gstatic.com',
      ],
      connectSrc: [
        "'self'",
        'https://www.google-analytics.com',
        'https://*.google-analytics.com',
        'https://*.analytics.google.com',
        'wss://*.mejora-masculina.com',
      ],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      frameSrc: [
        "'self'",
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/',
      ],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: true,
    },
  },
  
  // Session Management
  SESSION: {
    COOKIE_NAME: '__Secure-session-id',
    HTTP_ONLY: true,
    SECURE: true, // Only send over HTTPS
    SAME_SITE: 'Strict',
    MAX_AGE: 60 * 60 * 24 * 7, // 7 days
    DOMAIN: process.env.COOKIE_DOMAIN || '.mejora-masculina.com',
  },
  
  // CSRF Protection
  CSRF: {
    COOKIE_NAME: '__Host-csrf-token',
    HEADER_NAME: 'X-CSRF-Token',
    SAME_SITE: 'Strict',
    SECURE: true,
    HTTP_ONLY: false, // Needs to be accessible via JavaScript
  },
  
  // Rate Limiting for Authentication Endpoints
  AUTH_RATE_LIMIT: {
    WINDOW_MS: 60 * 60 * 1000, // 1 hour
    MAX_ATTEMPTS: 10, // Max login attempts per IP per windowMs
    DELAY_AFTER: 5, // Start delaying after 5 attempts
    DELAY_MS: 3000, // Delay each request by 3 seconds
  },
  
  // MFA Configuration
  MFA: {
    REQUIRED_FOR_ADMIN: true,
    REQUIRED_FOR_USERS: false,
    TOTP: {
      ISSUER: 'MejoraMasculina',
      DIGITS: 6,
      STEP: 30, // 30 seconds
      WINDOW: 1, // Allow 1 step before/after current time
    },
    SMS: {
      PROVIDER: 'twilio', // or 'aws-sns', 'nexmo', etc.
      TEMPLATE: 'Your verification code is: {code}',
      CODE_LENGTH: 6,
      CODE_EXPIRY: 5 * 60 * 1000, // 5 minutes
    },
  },
  
  // Security Logging
  LOGGING: {
    SENSITIVE_FIELDS: ['password', 'newPassword', 'currentPassword', 'token'],
    LOG_LEVEL: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
  },
  
  // API Security
  API: {
    VERSION: 'v1',
    BASE_PATH: '/api',
    RATE_LIMIT: {
      WINDOW_MS: 15 * 60 * 1000, // 15 minutes
      MAX: 100, // Limit each IP to 100 requests per windowMs
    },
  },
  
  // OAuth Providers
  OAUTH_PROVIDERS: {
    GOOGLE: {
      CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
      CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
      CALLBACK_URL: '/api/v1/auth/google/callback',
      SCOPE: ['profile', 'email'],
    },
    FACEBOOK: {
      CLIENT_ID: process.env.FACEBOOK_APP_ID || '',
      CLIENT_SECRET: process.env.FACEBOOK_APP_SECRET || '',
      CALLBACK_URL: '/api/v1/auth/facebook/callback',
      SCOPE: ['email', 'public_profile'],
      PROFILE_FIELDS: ['id', 'emails', 'name'],
    },
  },
  
  // Email Service Configuration
  EMAIL: {
    PROVIDER: 'sendgrid', // or 'mailgun', 'ses', 'smtp'
    FROM: 'no-reply@mejora-masculina.com',
    VERIFICATION_EXPIRY: 24 * 60 * 60 * 1000, // 24 hours
    PASSWORD_RESET_EXPIRY: 1 * 60 * 60 * 1000, // 1 hour
    TEMPLATES: {
      VERIFICATION: 'verification-email',
      PASSWORD_RESET: 'password-reset',
      WELCOME: 'welcome-email',
      MFA_CODE: 'mfa-code',
    },
  },
  
  // Database Security
  DATABASE: {
    CONNECTION_LIMIT: 10,
    ACQUIRE_TIMEOUT: 10000, // 10 seconds
    CONNECT_TIMEOUT: 10000, // 10 seconds
    TIMEOUT: 10000, // 10 seconds
    SSL: process.env.NODE_ENV === 'production' ? {
      rejectUnauthorized: true,
      ca: process.env.DB_SSL_CA,
      cert: process.env.DB_SSL_CERT,
      key: process.env.DB_SSL_KEY,
    } : false,
  },
  
  // Request Validation
  VALIDATION: {
    MAX_BODY_SIZE: '10mb',
    STRIP_UNKNOWN: true,
    ABORT_EARLY: false,
  },
  
  // Security Headers Middleware Options
  SECURE_HEADERS: {
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    ieNoOpen: true,
    noSniff: true,
    xssFilter: true,
  },
};

// Freeze the configuration to prevent modifications
Object.freeze(SecurityConfig);
Object.freeze(SecurityConfig.JWT);
Object.freeze(SecurityConfig.PASSWORD_POLICY);
Object.freeze(SecurityConfig.RATE_LIMIT);
Object.freeze(SecurityConfig.CORS);
Object.freeze(SecurityConfig.HEADERS);
Object.freeze(SecurityConfig.HEADERS.CONTENT_SECURITY_POLICY);
Object.freeze(SecurityConfig.SESSION);
Object.freeze(SecurityConfig.CSRF);
Object.freeze(SecurityConfig.AUTH_RATE_LIMIT);
Object.freeze(SecurityConfig.MFA);
Object.freeze(SecurityConfig.MFA.TOTP);
Object.freeze(SecurityConfig.MFA.SMS);
Object.freeze(SecurityConfig.LOGGING);
Object.freeze(SecurityConfig.API);
Object.freeze(SecurityConfig.API.RATE_LIMIT);
Object.freeze(SecurityConfig.OAUTH_PROVIDERS);
Object.freeze(SecurityConfig.OAUTH_PROVIDERS.GOOGLE);
Object.freeze(SecurityConfig.OAUTH_PROVIDERS.FACEBOOK);
Object.freeze(SecurityConfig.EMAIL);
Object.freeze(SecurityConfig.EMAIL.TEMPLATES);
Object.freeze(SecurityConfig.DATABASE);
Object.freeze(SecurityConfig.VALIDATION);
Object.freeze(SecurityConfig.SECURE_HEADERS);
