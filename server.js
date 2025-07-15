const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cluster = require('cluster');
const os = require('os');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Production configuration
const PRODUCTION_CONFIG = {
  // Cache settings
  CACHE_TTL: 24 * 60 * 60 * 1000, // 24 hours for production
  MAX_CACHE_SIZE: 10000, // Increased for production
  
  // Rate limiting (per hour for production scale)
  RATE_LIMIT_WINDOW: 60 * 60 * 1000, // 1 hour
  MAX_REQUESTS_PER_HOUR: 1000, // 1000 requests per hour per IP
  
  // API timeouts
  SMARTYSTREETS_TIMEOUT: 5000, // Faster timeout for production
  NOMINATIM_TIMEOUT: 8000,
  
  // Retry settings
  MAX_RETRIES: 2,
  RETRY_DELAY: 1000,
  
  // Logging
  ENABLE_REQUEST_LOGGING: process.env.NODE_ENV === 'production'
};

// Enable clustering for production
if (process.env.NODE_ENV === 'production' && cluster.isMaster) {
  const numCPUs = Math.min(os.cpus().length, 4); // Max 4 workers for cost efficiency
  
  console.log(`🚀 Master process ${process.pid} starting ${numCPUs} workers`);
  
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
  
  return; // Exit master process
}

// Worker process continues here
app.set('trust proxy', true);

// Enhanced CORS for production
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://localhost:3000',
      'http://localhost:3000',
      // Add your production domains
      process.env.FRONTEND_URL,
      /^https:\/\/.*\.hubspot\.com$/,
      /^https:\/\/.*\.hubspotpreview-na1\.com$/
    ].filter(Boolean);
    
    const isAllowed = allowedOrigins.some(allowed => {
      if (typeof allowed === 'string') return allowed === origin;
      if (allowed instanceof RegExp) return allowed.test(origin);
      return false;
    });
    
    if (isAllowed) {
      return callback(null, true);
    }
    
    if (process.env.NODE_ENV !== 'production') {
      console.log('Allowing origin for development:', origin);
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  maxAge: 86400 // Cache preflight for 24 hours
}));

app.use(express.json({ limit: '1mb' })); // Reduced limit for production
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Production-grade rate limiting with Redis-like structure
class ProductionRateLimit {
  constructor() {
    this.store = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000); // Cleanup every 5 minutes
  }
  
  cleanup() {
    const now = Date.now();
    for (const [key, data] of this.store.entries()) {
      if (now > data.resetTime) {
        this.store.delete(key);
      }
    }
  }
  
  checkLimit(clientIP) {
    const now = Date.now();
    const key = `rate_limit:${clientIP}`;
    
    if (!this.store.has(key)) {
      this.store.set(key, {
        count: 1,
        resetTime: now + PRODUCTION_CONFIG.RATE_LIMIT_WINDOW
      });
      return { allowed: true, remaining: PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR - 1 };
    }
    
    const data = this.store.get(key);
    
    if (now > data.resetTime) {
      data.count = 1;
      data.resetTime = now + PRODUCTION_CONFIG.RATE_LIMIT_WINDOW;
      return { allowed: true, remaining: PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR - 1 };
    }
    
    if (data.count >= PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR) {
      return {
        allowed: false,
        remaining: 0,
        retryAfter: Math.ceil((data.resetTime - now) / 1000)
      };
    }
    
    data.count++;
    return {
      allowed: true,
      remaining: PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR - data.count
    };
  }
}

const rateLimiter = new ProductionRateLimit();

function productionRateLimit(req, res, next) {
  const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
  const result = rateLimiter.checkLimit(clientIP);
  
  // Add rate limit headers
  res.set({
    'X-RateLimit-Limit': PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR,
    'X-RateLimit-Remaining': result.remaining,
    'X-RateLimit-Reset': new Date(Date.now() + PRODUCTION_CONFIG.RATE_LIMIT_WINDOW).toISOString()
  });
  
  if (!result.allowed) {
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: `Maximum ${PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR} requests per hour exceeded`,
      retryAfter: result.retryAfter,
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }
  
  next();
}

app.use('/api/', productionRateLimit);

// Production-grade caching with TTL and size management
class ProductionCache {
  constructor() {
    this.store = new Map();
    this.accessOrder = new Map(); // For LRU eviction
    this.cleanupInterval = setInterval(() => this.cleanup(), 10 * 60 * 1000); // Cleanup every 10 minutes
  }
  
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, data] of this.store.entries()) {
      if (now - data.timestamp > PRODUCTION_CONFIG.CACHE_TTL) {
        this.store.delete(key);
        this.accessOrder.delete(key);
        cleaned++;
      }
    }
    
    // LRU eviction if still too large
    if (this.store.size > PRODUCTION_CONFIG.MAX_CACHE_SIZE) {
      const sortedByAccess = Array.from(this.accessOrder.entries())
        .sort((a, b) => a[1] - b[1])
        .slice(0, this.store.size - PRODUCTION_CONFIG.MAX_CACHE_SIZE);
      
      for (const [key] of sortedByAccess) {
        this.store.delete(key);
        this.accessOrder.delete(key);
      }
    }
    
    if (cleaned > 0) {
      console.log(`Cache cleanup: removed ${cleaned} expired entries`);
    }
  }
  
  get(key) {
    const data = this.store.get(key);
    if (!data) return null;
    
    const now = Date.now();
    if (now - data.timestamp > PRODUCTION_CONFIG.CACHE_TTL) {
      this.store.delete(key);
      this.accessOrder.delete(key);
      return null;
    }
    
    this.accessOrder.set(key, now); // Update access time
    return data.value;
  }
  
  set(key, value) {
    const now = Date.now();
    
    // Evict oldest if at capacity
    if (this.store.size >= PRODUCTION_CONFIG.MAX_CACHE_SIZE && !this.store.has(key)) {
      const oldestKey = Array.from(this.accessOrder.entries())
        .sort((a, b) => a[1] - b[1])[0]?.[0];
      
      if (oldestKey) {
        this.store.delete(oldestKey);
        this.accessOrder.delete(oldestKey);
      }
    }
    
    this.store.set(key, { value, timestamp: now });
    this.accessOrder.set(key, now);
  }
  
  getStats() {
    return {
      size: this.store.size,
      maxSize: PRODUCTION_CONFIG.MAX_CACHE_SIZE,
      ttl: PRODUCTION_CONFIG.CACHE_TTL / 1000 + 's'
    };
  }
}

const cache = new ProductionCache();

// Async retry utility
async function retryAsync(fn, maxRetries = PRODUCTION_CONFIG.MAX_RETRIES) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt <= maxRetries) {
        const delay = PRODUCTION_CONFIG.RETRY_DELAY * attempt;
        console.log(`Attempt ${attempt} failed, retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw lastError;
}

// Enhanced address formatting with validation
function formatSmartyStreetsAddress(addressData) {
  try {
    if (!addressData?.components) return null;
    
    const address = (addressData.delivery_line_1 || '').trim();
    if (!address) return null; // Skip if no street address
    
    return {
      address: address + (addressData.delivery_line_2 ? ` ${addressData.delivery_line_2.trim()}` : ''),
      city: (addressData.components.city_name || '').trim(),
      state: addressData.components.state_abbreviation || 'OH',
      zipcode: (addressData.components.zipcode || '').trim(),
      verified: true,
      source: 'smartystreets'
    };
  } catch (error) {
    console.error('Error formatting SmartyStreets address:', error);
    return null;
  }
}

function formatNominatimAddress(addressData) {
  try {
    if (!addressData?.address) return null;
    
    const addr = addressData.address;
    
    // Build street address
    let streetAddress = '';
    if (addr.house_number && addr.road) {
      streetAddress = `${addr.house_number.trim()} ${addr.road.trim()}`;
    } else if (addr.road) {
      streetAddress = addr.road.trim();
    } else {
      // Fallback to display name first part
      const displayParts = addressData.display_name?.split(',') || [];
      streetAddress = displayParts[0]?.trim() || '';
    }
    
    if (!streetAddress) return null; // Skip if no street address
    
    // Get city with priority order
    const city = (addr.city || addr.town || addr.village || addr.municipality || '').trim();
    
    // Handle state normalization
    let state = (addr.state || '').trim();
    if (state.toLowerCase() === 'ohio') {
      state = 'OH';
    }
    
    return {
      address: streetAddress,
      city: city,
      state: state,
      zipcode: (addr.postcode || '').trim(),
      verified: false,
      source: 'nominatim'
    };
  } catch (error) {
    console.error('Error formatting Nominatim address:', error);
    return null;
  }
}

// Request logging for production monitoring
function requestLogger(req, res, next) {
  if (!PRODUCTION_CONFIG.ENABLE_REQUEST_LOGGING) return next();
  
  const start = Date.now();
  const clientIP = req.ip || 'unknown';
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: clientIP,
      userAgent: req.get('User-Agent') || 'unknown'
    };
    
    console.log(JSON.stringify(logData));
  });
  
  next();
}

app.use('/api/', requestLogger);

// Health check with detailed metrics
app.get('/api/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    success: true,
    status: 'healthy',
    service: 'Ohio Address API',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    worker: process.pid,
    uptime: {
      seconds: Math.floor(uptime),
      formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
    },
    cache: cache.getStats(),
    memory: {
      used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
      external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`
    },
    providers: {
      smartystreets: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
      nominatim: true
    },
    rateLimit: {
      window: `${PRODUCTION_CONFIG.RATE_LIMIT_WINDOW / 1000}s`,
      maxRequests: PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR
    }
  });
});

// Production-optimized address search endpoint
app.get('/api/ohio-address-suggestions', async (req, res) => {
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  console.log(`[${requestId}] Address search started`);
  
  try {
    const { query, limit = 5 } = req.query;
    
    // Input validation
    if (!query?.trim() || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Invalid query',
        message: 'Query must be at least 2 characters long',
        code: 'INVALID_QUERY'
      });
    }
    
    const normalizedQuery = query.trim().toLowerCase();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `ohio_addr:${normalizedQuery}:${resultLimit}`;
    
    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached) {
      console.log(`[${requestId}] Cache hit`);
      return res.json({
        success: true,
        suggestions: cached,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          count: cached.length,
          requestId
        }
      });
    }
    
    let suggestions = [];
    let metadata = {
      query: normalizedQuery,
      count: 0,
      attempts: [],
      requestId
    };
    
    // Try SmartyStreets first (if configured)
    const smartyConfigured = !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN);
    
    if (smartyConfigured) {
      try {
        console.log(`[${requestId}] Attempting SmartyStreets lookup`);
        
        const smartyResults = await retryAsync(async () => {
          const response = await axios.get('https://us-street.api.smartystreets.com/street-address', {
            params: {
              'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
              'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
              street: query.trim(),
              state: 'OH',
              candidates: resultLimit
            },
            timeout: PRODUCTION_CONFIG.SMARTYSTREETS_TIMEOUT,
            headers: { 'User-Agent': 'OhioEnergyAPI/2.0' }
          });
          return response.data;
        });
        
        if (Array.isArray(smartyResults) && smartyResults.length > 0) {
          const formatted = smartyResults
            .map(formatSmartyStreetsAddress)
            .filter(Boolean)
            .slice(0, resultLimit);
          
          if (formatted.length > 0) {
            suggestions = formatted;
            metadata.source = 'smartystreets';
            metadata.count = formatted.length;
            metadata.verified = true;
            
            cache.set(cacheKey, suggestions);
            console.log(`[${requestId}] SmartyStreets success: ${formatted.length} results`);
            
            return res.json({ success: true, suggestions, metadata });
          }
        }
        
      } catch (error) {
        console.error(`[${requestId}] SmartyStreets error:`, error.message);
        metadata.attempts.push(`smartystreets_error: ${error.message}`);
      }
    }
    
    // Fallback to Nominatim
    try {
      console.log(`[${requestId}] Attempting Nominatim lookup`);
      
      const nominatimResults = await retryAsync(async () => {
        const response = await axios.get('https://nominatim.openstreetmap.org/search', {
          params: {
            q: `${query.trim()}, Ohio, USA`,
            format: 'json',
            addressdetails: 1,
            limit: resultLimit,
            countrycodes: 'us'
          },
          timeout: PRODUCTION_CONFIG.NOMINATIM_TIMEOUT,
          headers: { 'User-Agent': 'OhioEnergyAPI/2.0' }
        });
        return response.data;
      });
      
      if (Array.isArray(nominatimResults) && nominatimResults.length > 0) {
        const ohioAddresses = nominatimResults
          .filter(addr => {
            const state = addr.address?.state?.toLowerCase();
            return state && (state.includes('ohio') || state === 'oh');
          })
          .map(formatNominatimAddress)
          .filter(Boolean)
          .slice(0, resultLimit);
        
        suggestions = ohioAddresses;
        metadata.source = 'nominatim';
        metadata.count = ohioAddresses.length;
        metadata.verified = false;
        
        if (ohioAddresses.length > 0) {
          cache.set(cacheKey, suggestions);
        }
        
        console.log(`[${requestId}] Nominatim success: ${ohioAddresses.length} results`);
      }
      
    } catch (error) {
      console.error(`[${requestId}] Nominatim error:`, error.message);
      metadata.attempts.push(`nominatim_error: ${error.message}`);
    }
    
    console.log(`[${requestId}] Final result: ${suggestions.length} suggestions`);
    
    res.json({
      success: true,
      suggestions,
      metadata
    });
    
  } catch (error) {
    console.error(`[${requestId}] Unexpected error:`, error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Address search failed',
      code: 'INTERNAL_ERROR'
    });
  }
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Production Ohio Address API',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    worker: process.pid,
    environment: process.env.NODE_ENV || 'development',
    config: {
      smartystreets: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
      cacheSize: cache.getStats().size,
      rateLimit: `${PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR}/hour`
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '2.0.0',
    status: 'operational',
    endpoints: ['/api/test', '/api/health', '/api/ohio-address-suggestions']
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error:', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl
  });
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'GLOBAL_ERROR'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND'
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
PRODUCTION OHIO ADDRESS API
Worker: ${process.pid}
Port: ${PORT}
Environment: ${process.env.NODE_ENV || 'development'}
Cache: ${PRODUCTION_CONFIG.MAX_CACHE_SIZE} entries, ${PRODUCTION_CONFIG.CACHE_TTL / 1000}s TTL
Rate Limit: ${PRODUCTION_CONFIG.MAX_REQUESTS_PER_HOUR}/hour per IP
Retry: ${PRODUCTION_CONFIG.MAX_RETRIES} attempts
Ready for production traffic!
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log(`Worker ${process.pid} shutting down gracefully`);
  server.close(() => {
    if (cache.cleanupInterval) clearInterval(cache.cleanupInterval);
    if (rateLimiter.cleanupInterval) clearInterval(rateLimiter.cleanupInterval);
    process.exit(0);
  });
});

module.exports = app;
