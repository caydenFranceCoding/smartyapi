const express = require('express');
const cors = require('cors');
const axios = require('axios');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cluster = require('cluster');
const os = require('os');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Production vs Development Configuration
const CONFIG = {
  // Cache settings
  CACHE_TTL: isProduction ? 24 * 60 * 60 * 1000 : 6 * 60 * 60 * 1000,
  MAX_CACHE_SIZE: isProduction ? 5000 : 1000,
  
  // Rate limiting
  RATE_LIMIT_WINDOW: isProduction ? 60 * 60 * 1000 : 15 * 60 * 1000, // 1 hour vs 15 min
  MAX_REQUESTS_PER_WINDOW: isProduction ? 1000 : 100,
  
  // API timeouts
  SMARTYSTREETS_TIMEOUT: isProduction ? 8000 : 3000,
  NOMINATIM_TIMEOUT: isProduction ? 10000 : 4000,
  
  // Retry settings
  MAX_RETRIES: isProduction ? 3 : 1,
  RETRY_DELAY: isProduction ? 1000 : 500,
  
  // Keep-alive (only for free tier)
  KEEP_ALIVE_INTERVAL: isProduction ? null : 14 * 60 * 1000,
  
  // Security
  ENABLE_CLUSTERING: isProduction,
  ENABLE_COMPRESSION: isProduction,
  ENABLE_DETAILED_LOGGING: isProduction,
  TRUST_PROXY: isProduction
};

// Clustering for production
if (CONFIG.ENABLE_CLUSTERING && cluster.isMaster) {
  const numCPUs = Math.min(os.cpus().length, 4);
  console.log(`🚀 Master ${process.pid} starting ${numCPUs} workers`);
  
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
  
  return;
}

// Security middleware for production
if (isProduction) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }));
}

// Compression for production
if (CONFIG.ENABLE_COMPRESSION) {
  app.use(compression());
}

// Trust proxy setting
if (CONFIG.TRUST_PROXY) {
  app.set('trust proxy', true);
}

// Enhanced CORS for production
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    // Production whitelist
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://wattkarma.com',
      'https://www.wattkarma.com',
      process.env.FRONTEND_URL,
      process.env.CLIENT_URL,
      // Regex patterns for subdomains
      /^https:\/\/.*\.hubspot\.com$/,
      /^https:\/\/.*\.hubspotpreview-na1\.com$/,
      /^https:\/\/.*\.wattkarma\.com$/
    ].filter(Boolean);
    
    // Development: allow localhost
    if (!isProduction) {
      allowedOrigins.push(
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3000'
      );
    }
    
    const isAllowed = allowedOrigins.some(allowed => {
      if (typeof allowed === 'string') {
        return origin === allowed || origin.startsWith(allowed);
      }
      if (allowed instanceof RegExp) {
        return allowed.test(origin);
      }
      return false;
    });
    
    if (isAllowed) {
      return callback(null, true);
    }
    
    // Log rejected origins in production
    if (isProduction) {
      console.warn(`CORS rejected origin: ${origin}`);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  maxAge: isProduction ? 86400 : 3600 // Cache preflight longer in production
}));

// Body parsing with appropriate limits
app.use(express.json({ 
  limit: isProduction ? '1mb' : '100kb',
  type: ['application/json', 'text/plain']
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: isProduction ? '1mb' : '100kb' 
}));

// Production-grade rate limiting
// Redis store for rate limiting (optional)
let redisStore;
if (process.env.REDIS_URL && isProduction) {
  try {
    const { createClient } = require('redis');
    const RedisStore = require('rate-limit-redis');
    
    const redisClient = createClient({
      url: process.env.REDIS_URL,
      socket: { connectTimeout: 5000 }
    });
    
    redisClient.on('error', (err) => {
      console.error('Redis error:', err);
    });
    
    redisStore = new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    });
    
    console.log('✅ Redis rate limiting enabled');
  } catch (error) {
    console.warn('⚠️  Redis setup failed, using memory store:', error.message);
  }
}

const limiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW,
  max: CONFIG.MAX_REQUESTS_PER_WINDOW,
  message: {
    success: false,
    error: 'Too many requests',
    retryAfter: CONFIG.RATE_LIMIT_WINDOW / 1000
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: redisStore, // Uses Redis if available, otherwise memory
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/api/health' || req.path === '/api/ping';
  }
});

app.use('/api/', limiter);

// Production cache with better memory management
class ProductionCache {
  constructor() {
    this.store = new Map();
    this.accessTimes = new Map();
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0
    };
    
    // Cleanup interval based on environment
    const cleanupInterval = isProduction ? 10 * 60 * 1000 : 30 * 60 * 1000;
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupInterval);
  }
  
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    
    // Remove expired entries
    for (const [key, data] of this.store.entries()) {
      if (now - data.timestamp > CONFIG.CACHE_TTL) {
        this.store.delete(key);
        this.accessTimes.delete(key);
        cleaned++;
      }
    }
    
    // LRU eviction if over capacity
    if (this.store.size > CONFIG.MAX_CACHE_SIZE) {
      const sortedByAccess = Array.from(this.accessTimes.entries())
        .sort((a, b) => a[1] - b[1])
        .slice(0, this.store.size - CONFIG.MAX_CACHE_SIZE);
      
      for (const [key] of sortedByAccess) {
        this.store.delete(key);
        this.accessTimes.delete(key);
        this.stats.evictions++;
      }
    }
    
    if (cleaned > 0 && CONFIG.ENABLE_DETAILED_LOGGING) {
      console.log(`Cache cleanup: removed ${cleaned} expired entries`);
    }
  }
  
  get(key) {
    const data = this.store.get(key);
    if (!data) {
      this.stats.misses++;
      return null;
    }
    
    const now = Date.now();
    if (now - data.timestamp > CONFIG.CACHE_TTL) {
      this.store.delete(key);
      this.accessTimes.delete(key);
      this.stats.misses++;
      return null;
    }
    
    this.accessTimes.set(key, now);
    this.stats.hits++;
    return data.value;
  }
  
  set(key, value) {
    const now = Date.now();
    
    // Pre-evict if at capacity
    if (this.store.size >= CONFIG.MAX_CACHE_SIZE && !this.store.has(key)) {
      const oldestKey = Array.from(this.accessTimes.entries())
        .sort((a, b) => a[1] - b[1])[0]?.[0];
      
      if (oldestKey) {
        this.store.delete(oldestKey);
        this.accessTimes.delete(oldestKey);
        this.stats.evictions++;
      }
    }
    
    this.store.set(key, { value, timestamp: now });
    this.accessTimes.set(key, now);
  }
  
  getStats() {
    const hitRate = this.stats.hits + this.stats.misses > 0 
      ? (this.stats.hits / (this.stats.hits + this.stats.misses) * 100).toFixed(1)
      : '0.0';
    
    return {
      size: this.store.size,
      maxSize: CONFIG.MAX_CACHE_SIZE,
      hitRate: `${hitRate}%`,
      ...this.stats
    };
  }
  
  destroy() {
    clearInterval(this.cleanupTimer);
    this.store.clear();
    this.accessTimes.clear();
  }
}

const cache = new ProductionCache();

// Enhanced retry with exponential backoff
async function retryWithBackoff(fn, maxRetries = CONFIG.MAX_RETRIES) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt <= maxRetries) {
        const delay = CONFIG.RETRY_DELAY * Math.pow(2, attempt - 1); // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw lastError;
}

// Pre-configured axios instances with production settings
const smartyAxios = axios.create({
  baseURL: 'https://us-street.api.smartystreets.com',
  timeout: CONFIG.SMARTYSTREETS_TIMEOUT,
  headers: { 
    'User-Agent': 'OhioEnergyAPI/2.1',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip, deflate'
  }
});

const nominatimAxios = axios.create({
  baseURL: 'https://nominatim.openstreetmap.org',
  timeout: CONFIG.NOMINATIM_TIMEOUT,
  headers: { 
    'User-Agent': 'OhioEnergyAPI/2.1',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip, deflate'
  }
});

// Request logging middleware for production
function requestLogger(req, res, next) {
  if (!CONFIG.ENABLE_DETAILED_LOGGING) return next();
  
  const start = Date.now();
  const { method, originalUrl, ip } = req;
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      timestamp: new Date().toISOString(),
      method,
      url: originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip,
      userAgent: req.get('User-Agent'),
      worker: process.pid
    };
    
    console.log(JSON.stringify(logData));
  });
  
  next();
}

app.use('/api/', requestLogger);

// Enhanced address formatting with validation
function formatSmartyStreetsAddress(data) {
  try {
    if (!data?.components || !data.delivery_line_1?.trim()) return null;
    
    const address = data.delivery_line_1.trim();
    const unit = data.delivery_line_2?.trim();
    
    return {
      address: address + (unit ? ` ${unit}` : ''),
      city: (data.components.city_name || '').trim(),
      state: data.components.state_abbreviation || 'OH',
      zipcode: (data.components.zipcode || '').trim(),
      verified: true,
      source: 'smartystreets',
      confidence: data.analysis?.dpv_match_y ? 'high' : 'medium'
    };
  } catch (error) {
    console.error('SmartyStreets formatting error:', error);
    return null;
  }
}

function formatNominatimAddress(data) {
  try {
    if (!data?.address) return null;
    
    const addr = data.address;
    let streetAddress = '';
    
    if (addr.house_number && addr.road) {
      streetAddress = `${addr.house_number.trim()} ${addr.road.trim()}`;
    } else if (addr.road) {
      streetAddress = addr.road.trim();
    } else {
      const displayParts = data.display_name?.split(',') || [];
      streetAddress = displayParts[0]?.trim() || '';
    }
    
    if (!streetAddress) return null;
    
    const city = (addr.city || addr.town || addr.village || addr.municipality || '').trim();
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
      source: 'nominatim',
      confidence: 'low'
    };
  } catch (error) {
    console.error('Nominatim formatting error:', error);
    return null;
  }
}

// Keep-alive for free tier only
function setupKeepAlive() {
  if (CONFIG.KEEP_ALIVE_INTERVAL && process.env.RENDER_SERVICE_URL) {
    setInterval(async () => {
      try {
        await axios.get(`${process.env.RENDER_SERVICE_URL}/api/ping`, { 
          timeout: 5000,
          headers: { 'User-Agent': 'KeepAlive/1.0' }
        });
        console.log('Keep-alive ping successful');
      } catch (error) {
        console.log('Keep-alive ping failed:', error.message);
      }
    }, CONFIG.KEEP_ALIVE_INTERVAL);
    
    console.log('Keep-alive enabled for free tier');
  }
}

// Comprehensive health check
app.get('/api/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    success: true,
    status: 'healthy',
    service: 'Ohio Address API',
    version: '2.1.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    worker: process.pid,
    uptime: {
      seconds: Math.floor(uptime),
      formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`
    },
    memory: {
      used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
    },
    cache: cache.getStats(),
    providers: {
      smartystreets: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
      nominatim: true
    },
    config: {
      clustering: CONFIG.ENABLE_CLUSTERING,
      rateLimit: `${CONFIG.MAX_REQUESTS_PER_WINDOW}/${CONFIG.RATE_LIMIT_WINDOW / 60000}min`,
      cacheSize: CONFIG.MAX_CACHE_SIZE
    }
  });
});

// Simple ping for monitoring
app.get('/api/ping', (req, res) => {
  res.json({ 
    success: true, 
    timestamp: Date.now(),
    worker: process.pid 
  });
});

// Main address search endpoint
app.get('/api/ohio-address-suggestions', async (req, res) => {
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
  
  try {
    const { query, limit = 5 } = req.query;
    
    // Enhanced input validation
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Invalid query parameter',
        message: 'Query must be a string with at least 2 characters',
        code: 'INVALID_QUERY'
      });
    }
    
    const normalizedQuery = query.trim().toLowerCase();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), isProduction ? 10 : 8);
    const cacheKey = `ohio_addr:${normalizedQuery}:${resultLimit}`;
    
    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        suggestions: cached,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          count: cached.length,
          requestId,
          cached: true
        }
      });
    }
    
    let suggestions = [];
    let metadata = {
      query: normalizedQuery,
      count: 0,
      requestId,
      cached: false,
      providers: []
    };
    
    // Try SmartyStreets first
    const smartyConfigured = !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN);
    
    if (smartyConfigured) {
      try {
        const response = await retryWithBackoff(() =>
          smartyAxios.get('/street-address', {
            params: {
              'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
              'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
              street: query.trim(),
              state: 'OH',
              candidates: resultLimit
            }
          })
        );
        
        if (Array.isArray(response.data) && response.data.length > 0) {
          const formatted = response.data
            .map(formatSmartyStreetsAddress)
            .filter(Boolean)
            .slice(0, resultLimit);
          
          if (formatted.length > 0) {
            suggestions = formatted;
            metadata.source = 'smartystreets';
            metadata.count = formatted.length;
            metadata.providers.push('smartystreets');
            
            cache.set(cacheKey, suggestions);
            
            return res.json({ success: true, suggestions, metadata });
          }
        }
        
        metadata.providers.push('smartystreets_no_results');
        
      } catch (error) {
        console.error(`[${requestId}] SmartyStreets error:`, error.message);
        metadata.providers.push(`smartystreets_error`);
      }
    }
    
    // Fallback to Nominatim
    try {
      const response = await retryWithBackoff(() =>
        nominatimAxios.get('/search', {
          params: {
            q: `${query.trim()}, Ohio, USA`,
            format: 'json',
            addressdetails: 1,
            limit: resultLimit + 2, // Get a few extra to filter
            countrycodes: 'us'
          }
        })
      );
      
      if (Array.isArray(response.data) && response.data.length > 0) {
        const ohioAddresses = response.data
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
        metadata.providers.push('nominatim');
        
        if (ohioAddresses.length > 0) {
          cache.set(cacheKey, suggestions);
        }
      } else {
        metadata.providers.push('nominatim_no_results');
      }
      
    } catch (error) {
      console.error(`[${requestId}] Nominatim error:`, error.message);
      metadata.providers.push('nominatim_error');
    }
    
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
      code: 'INTERNAL_ERROR',
      requestId
    });
  }
});

// API documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '2.1.0',
    documentation: {
      endpoints: {
        'GET /api/ohio-address-suggestions': {
          description: 'Search for Ohio address suggestions',
          parameters: {
            query: 'string (required, min 2 chars)',
            limit: 'number (optional, 1-10, default 5)'
          },
          example: '/api/ohio-address-suggestions?query=123%20Main&limit=5'
        },
        'GET /api/health': 'Health check with system stats',
        'GET /api/ping': 'Simple ping endpoint'
      }
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '2.1.0',
    status: 'operational',
    environment: process.env.NODE_ENV || 'development',
    docs: '/api/docs'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  const errorId = `err_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
  
  console.error(`[${errorId}] Global error:`, {
    message: error.message,
    stack: CONFIG.ENABLE_DETAILED_LOGGING ? error.stack : undefined,
    url: req.originalUrl,
    method: req.method
  });
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'GLOBAL_ERROR',
    errorId: CONFIG.ENABLE_DETAILED_LOGGING ? errorId : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    availableEndpoints: ['/', '/api/health', '/api/ping', '/api/ohio-address-suggestions', '/api/docs']
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  const mode = isProduction ? 'PRODUCTION' : 'DEVELOPMENT';
  console.log(`
🚀 ${mode} OHIO ADDRESS API v2.1.0
Worker: ${process.pid}
Port: ${PORT}
Environment: ${process.env.NODE_ENV || 'development'}
Security: ${isProduction ? 'Enhanced' : 'Basic'}
Clustering: ${CONFIG.ENABLE_CLUSTERING ? 'Enabled' : 'Disabled'}
Cache: ${CONFIG.MAX_CACHE_SIZE} entries
Rate Limit: ${CONFIG.MAX_REQUESTS_PER_WINDOW}/${CONFIG.RATE_LIMIT_WINDOW / 60000}min
Ready!
  `);
  
  // Setup keep-alive only for free tier
  if (!isProduction) {
    setupKeepAlive();
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log(`Worker ${process.pid} shutting down gracefully...`);
  server.close(() => {
    cache.destroy();
    console.log('Shutdown complete');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log(`Worker ${process.pid} received SIGINT, shutting down...`);
  server.close(() => {
    cache.destroy();
    process.exit(0);
  });
});

module.exports = app;
