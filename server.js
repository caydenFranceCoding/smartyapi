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

const CONFIG = {
  CACHE_TTL: isProduction ? 24 * 60 * 60 * 1000 : 6 * 60 * 60 * 1000,
  MAX_CACHE_SIZE: isProduction ? 5000 : 1000,
  RATE_LIMIT_WINDOW: isProduction ? 60 * 60 * 1000 : 15 * 60 * 1000,
  MAX_REQUESTS_PER_WINDOW: isProduction ? 1000 : 100,
  SMARTYSTREETS_TIMEOUT: isProduction ? 10000 : 5000, // Increased timeout
  NOMINATIM_TIMEOUT: isProduction ? 5000 : 4000,
  MAX_RETRIES: isProduction ? 3 : 2, // Increased retries for dev
  RETRY_DELAY: isProduction ? 1000 : 500,
  KEEP_ALIVE_INTERVAL: isProduction ? null : 14 * 60 * 1000,
  ENABLE_CLUSTERING: isProduction,
  ENABLE_COMPRESSION: isProduction,
  ENABLE_DETAILED_LOGGING: isProduction,
  TRUST_PROXY: isProduction
};

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

if (CONFIG.ENABLE_COMPRESSION) {
  app.use(compression());
}

if (CONFIG.TRUST_PROXY) {
  app.set('trust proxy', true);
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://wattkarma.com',
      'https://www.wattkarma.com',
      process.env.FRONTEND_URL,
      process.env.CLIENT_URL,
      /^https:\/\/.*\.hubspot\.com$/,
      /^https:\/\/.*\.hubspotpreview-na1\.com$/,
      /^https:\/\/.*\.wattkarma\.com$/
    ].filter(Boolean);
    
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
    
    if (isProduction) {
      console.warn(`CORS rejected origin: ${origin}`);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  maxAge: isProduction ? 86400 : 3600
}));

app.use(express.json({ 
  limit: isProduction ? '1mb' : '100kb',
  type: ['application/json', 'text/plain']
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: isProduction ? '1mb' : '100kb' 
}));

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
    
    console.log('Redis rate limiting enabled');
  } catch (error) {
    console.warn('Redis setup failed, using memory store:', error.message);
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
  store: redisStore,
  keyGenerator: (req) => {
    const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';
    return `${ip}-${userAgent.slice(0, 50)}`;
  },
  skip: (req) => {
    return req.path === '/api/health' || req.path === '/api/ping';
  }
});

app.use('/api/', limiter);

class ProductionCache {
  constructor() {
    this.store = new Map();
    this.accessTimes = new Map();
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0
    };
    
    const cleanupInterval = isProduction ? 10 * 60 * 1000 : 30 * 60 * 1000;
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupInterval);
  }
  
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, data] of this.store.entries()) {
      if (now - data.timestamp > CONFIG.CACHE_TTL) {
        this.store.delete(key);
        this.accessTimes.delete(key);
        cleaned++;
      }
    }
    
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

async function retryWithBackoff(fn, maxRetries = CONFIG.MAX_RETRIES) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt <= maxRetries) {
        const delay = CONFIG.RETRY_DELAY * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        console.log(`SmartyStreets retry attempt ${attempt}/${maxRetries} after ${delay}ms delay`);
      }
    }
  }
  
  throw lastError;
}

// Enhanced SmartyStreets client with better error handling
const smartyAxios = axios.create({
  baseURL: 'https://us-street.api.smartystreets.com',
  timeout: CONFIG.SMARTYSTREETS_TIMEOUT,
  headers: { 
    'User-Agent': 'WattKarma-OhioEnergyAPI/2.1',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/json'
  }
});

const nominatimAxios = axios.create({
  baseURL: 'https://nominatim.openstreetmap.org',
  timeout: CONFIG.NOMINATIM_TIMEOUT,
  headers: { 
    'User-Agent': 'OhioEnergyAPI/2.1 (contact@wattkarma.com)',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip, deflate'
  }
});

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

// Enhanced SmartyStreets address formatter with better data extraction
function formatSmartyStreetsAddress(data) {
  try {
    if (!data?.components || !data.delivery_line_1?.trim()) return null;
    
    const address = data.delivery_line_1.trim();
    const unit = data.delivery_line_2?.trim();
    const city = (data.components.city_name || '').trim();
    const state = data.components.state_abbreviation || 'OH';
    const zipcode = (data.components.zipcode || '').trim();
    const zip4 = data.components.plus4_code ? `${zipcode}-${data.components.plus4_code}` : zipcode;
    
    // Enhanced confidence scoring based on SmartyStreets data quality indicators
    let confidence = 'medium';
    if (data.analysis?.dpv_match_y === 'Y' && data.analysis?.dpv_vacant === 'N') {
      confidence = 'high';
    } else if (data.analysis?.dpv_match_n === 'Y' || data.analysis?.dpv_vacant === 'Y') {
      confidence = 'low';
    }
    
    return {
      address: address + (unit ? ` ${unit}` : ''),
      city: city,
      state: state,
      zipcode: zip4,
      verified: true,
      source: 'smartystreets',
      confidence: confidence,
      metadata: {
        dpv_match: data.analysis?.dpv_match_y === 'Y',
        vacant: data.analysis?.dpv_vacant === 'Y',
        business: data.analysis?.dpv_cmra === 'Y',
        residential: data.analysis?.dpv_cmra !== 'Y',
        deliverable: data.analysis?.dpv_match_y === 'Y' && data.analysis?.dpv_vacant !== 'Y',
        county: data.components?.county_name,
        congressional_district: data.components?.congressional_district,
        rdi: data.analysis?.rdi
      }
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
      confidence: 'low',
      metadata: {
        lat: parseFloat(data.lat) || null,
        lon: parseFloat(data.lon) || null,
        display_name: data.display_name,
        importance: parseFloat(data.importance) || 0
      }
    };
  } catch (error) {
    console.error('Nominatim formatting error:', error);
    return null;
  }
}

function getFallbackOhioAddresses(query) {
  const commonOhioAddresses = [
    { address: "123 Main St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "fallback", confidence: "fallback" },
    { address: "456 High St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "fallback", confidence: "fallback" },
    { address: "789 Broad St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "fallback", confidence: "fallback" },
    { address: "321 Superior Ave", city: "Cleveland", state: "OH", zipcode: "44101", verified: false, source: "fallback", confidence: "fallback" },
    { address: "654 Euclid Ave", city: "Cleveland", state: "OH", zipcode: "44101", verified: false, source: "fallback", confidence: "fallback" },
    { address: "987 Vine St", city: "Cincinnati", state: "OH", zipcode: "45201", verified: false, source: "fallback", confidence: "fallback" },
    { address: "147 Race St", city: "Cincinnati", state: "OH", zipcode: "45201", verified: false, source: "fallback", confidence: "fallback" },
    { address: "258 Market St", city: "Akron", state: "OH", zipcode: "44301", verified: false, source: "fallback", confidence: "fallback" },
    { address: "369 Wayne Ave", city: "Dayton", state: "OH", zipcode: "45402", verified: false, source: "fallback", confidence: "fallback" },
    { address: "741 Madison Ave", city: "Toledo", state: "OH", zipcode: "43604", verified: false, source: "fallback", confidence: "fallback" }
  ];

  const queryLower = query.toLowerCase();
  
  return commonOhioAddresses.filter(addr => {
    const addressLower = `${addr.address} ${addr.city}`.toLowerCase();
    return addressLower.includes(queryLower) || 
           queryLower.split(' ').some(word => word.length > 2 && addressLower.includes(word));
  }).slice(0, 5);
}

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

// Enhanced SmartyStreets validation function
async function validateSmartyStreetsConfig() {
  const authId = process.env.SMARTYSTREETS_AUTH_ID;
  const authToken = process.env.SMARTYSTREETS_AUTH_TOKEN;
  
  if (!authId || !authToken) {
    console.warn('SmartyStreets credentials not found in environment variables');
    return false;
  }
  
  try {
    // Test the credentials with a simple validation call
    const testResponse = await smartyAxios.get('/street-address', {
      params: {
        'auth-id': authId,
        'auth-token': authToken,
        street: '1 Rosedale',
        city: 'Baltimore',
        state: 'MD',
        candidates: 1
      },
      timeout: 5000
    });
    
    console.log('✅ SmartyStreets credentials validated successfully');
    return true;
  } catch (error) {
    if (error.response?.status === 401) {
      console.error('❌ SmartyStreets authentication failed - check your credentials');
    } else if (error.response?.status === 402) {
      console.error('❌ SmartyStreets payment required - check your account balance');
    } else {
      console.warn(`⚠️ SmartyStreets validation inconclusive: ${error.message}`);
    }
    return false;
  }
}

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
      smartystreets: {
        configured: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
        authId: process.env.SMARTYSTREETS_AUTH_ID ? `${process.env.SMARTYSTREETS_AUTH_ID.substring(0, 4)}****` : 'not set',
        authToken: process.env.SMARTYSTREETS_AUTH_TOKEN ? '****' : 'not set'
      },
      nominatim: true,
      fallback: true
    },
    config: {
      clustering: CONFIG.ENABLE_CLUSTERING,
      rateLimit: `${CONFIG.MAX_REQUESTS_PER_WINDOW}/${CONFIG.RATE_LIMIT_WINDOW / 60000}min`,
      cacheSize: CONFIG.MAX_CACHE_SIZE
    }
  });
});

app.get('/api/ping', (req, res) => {
  res.json({ 
    success: true, 
    timestamp: Date.now(),
    worker: process.pid 
  });
});

// New endpoint to test SmartyStreets specifically
app.get('/api/test-smartystreets', async (req, res) => {
  const { address = '1 Rosedale', city = 'Baltimore', state = 'MD' } = req.query;
  
  const authId = process.env.SMARTYSTREETS_AUTH_ID;
  const authToken = process.env.SMARTYSTREETS_AUTH_TOKEN;
  
  if (!authId || !authToken) {
    return res.status(400).json({
      success: false,
      error: 'SmartyStreets credentials not configured',
      message: 'Please set SMARTYSTREETS_AUTH_ID and SMARTYSTREETS_AUTH_TOKEN environment variables'
    });
  }
  
  try {
    const response = await smartyAxios.get('/street-address', {
      params: {
        'auth-id': authId,
        'auth-token': authToken,
        street: address,
        city: city,
        state: state,
        candidates: 3
      }
    });
    
    const formatted = response.data.map(formatSmartyStreetsAddress).filter(Boolean);
    
    res.json({
      success: true,
      message: 'SmartyStreets API working correctly',
      test_query: { address, city, state },
      results: formatted,
      raw_response_count: response.data.length,
      formatted_count: formatted.length
    });
    
  } catch (error) {
    console.error('SmartyStreets test error:', error.response?.data || error.message);
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: 'SmartyStreets API error',
      message: error.response?.data?.message || error.message,
      status: error.response?.status,
      test_query: { address, city, state }
    });
  }
});

app.get('/api/test-fallback', (req, res) => {
  const { query = 'main' } = req.query;
  const suggestions = getFallbackOhioAddresses(query);
  
  res.json({
    success: true,
    suggestions: suggestions,
    metadata: {
      source: 'test-fallback',
      count: suggestions.length,
      query: query
    }
  });
});

app.get('/api/ohio-address-suggestions', async (req, res) => {
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
  
  try {
    const { query, limit = 5, format = 'standard' } = req.query;
    
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Invalid query parameter',
        message: 'Query must be a string with at least 2 characters',
        code: 'INVALID_QUERY'
      });
    }
    
    const normalizedQuery = query.trim().toLowerCase();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), isProduction ? 15 : 10);
    const cacheKey = `ohio_addr:${normalizedQuery}:${resultLimit}:${format}`;
    
    const cached = cache.get(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        addresses: cached.addresses,
        options: cached.options,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          count: cached.addresses.length,
          requestId,
          cached: true
        }
      });
    }
    
    let rawSuggestions = [];
    let metadata = {
      query: normalizedQuery,
      count: 0,
      requestId,
      cached: false,
      providers: []
    };
    
    const authId = process.env.SMARTYSTREETS_AUTH_ID;
    const authToken = process.env.SMARTYSTREETS_AUTH_TOKEN;
    const smartyConfigured = !!(authId && authToken);
    
    if (smartyConfigured) {
      try {
        console.log(`[${requestId}] Trying SmartyStreets for: "${normalizedQuery}"`);
        
        // Enhanced SmartyStreets query with better parameters
        const response = await retryWithBackoff(() =>
          smartyAxios.get('/street-address', {
            params: {
              'auth-id': authId,
              'auth-token': authToken,
              street: query.trim(),
              state: 'OH',
              candidates: Math.min(resultLimit + 5, 15), // Get extra to filter and sort
              match: 'enhanced' // Use enhanced matching for better results
            }
          })
        );
        
        if (Array.isArray(response.data) && response.data.length > 0) {
          const formatted = response.data
            .map(formatSmartyStreetsAddress)
            .filter(Boolean)
            .filter(addr => addr.state === 'OH') // Double check it's Ohio
            .sort((a, b) => {
              // Sort by confidence (high > medium > low)
              const confidenceOrder = { 'high': 3, 'medium': 2, 'low': 1 };
              const aScore = confidenceOrder[a.confidence] || 0;
              const bScore = confidenceOrder[b.confidence] || 0;
              return bScore - aScore;
            })
            .slice(0, resultLimit);
          
          if (formatted.length > 0) {
            rawSuggestions = formatted;
            metadata.source = 'smartystreets';
            metadata.count = formatted.length;
            metadata.providers.push('smartystreets');
            metadata.smartystreets_raw_count = response.data.length;
            console.log(`[${requestId}] SmartyStreets success: ${formatted.length} results`);
          }
        }
        
        if (rawSuggestions.length === 0) {
          console.log(`[${requestId}] SmartyStreets returned no Ohio addresses`);
          metadata.providers.push('smartystreets_no_ohio_results');
        }
        
      } catch (error) {
        console.error(`[${requestId}] SmartyStreets error:`, error.response?.status, error.message);
        metadata.providers.push(`smartystreets_error_${error.response?.status || 'unknown'}`);
        metadata.smartystreets_error = error.response?.data?.message || error.message;
      }
    } else {
      console.log(`[${requestId}] SmartyStreets not configured (missing credentials)`);
      metadata.providers.push('smartystreets_not_configured');
    }
    
    // Fall back to Nominatim if we don't have enough results
    if (rawSuggestions.length < 3) {
      try {
        console.log(`[${requestId}] Trying Nominatim for additional results: "${normalizedQuery}"`);
        
        const nominatimResponse = await Promise.race([
          nominatimAxios.get('/search', {
            params: {
              q: `${query.trim()}, Ohio, USA`,
              format: 'json',
              addressdetails: 1,
              limit: Math.min(resultLimit + 3, 10),
              countrycodes: 'us',
              'accept-language': 'en'
            }
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Nominatim timeout')), 4000)
          )
        ]);
        
        if (Array.isArray(nominatimResponse.data) && nominatimResponse.data.length > 0) {
          const ohioAddresses = nominatimResponse.data
            .filter(addr => {
              const state = addr.address?.state?.toLowerCase();
              return state && (state.includes('ohio') || state === 'oh');
            })
            .map(formatNominatimAddress)
            .filter(Boolean)
            .filter(addr => {
              // Avoid duplicates from SmartyStreets
              return !rawSuggestions.some(existing => 
                existing.address.toLowerCase() === addr.address.toLowerCase() &&
                existing.city.toLowerCase() === addr.city.toLowerCase()
              );
            });
          
          if (ohioAddresses.length > 0) {
            rawSuggestions = [...rawSuggestions, ...ohioAddresses].slice(0, resultLimit);
            metadata.providers.push('nominatim');
            metadata.nominatim_raw_count = nominatimResponse.data.length;
            console.log(`[${requestId}] Nominatim added ${ohioAddresses.length} additional results`);
          } else {
            metadata.providers.push('nominatim_no_ohio_results');
          }
        } else {
          metadata.providers.push('nominatim_no_results');
        }
        
      } catch (error) {
        console.error(`[${requestId}] Nominatim error:`, error.message);
        metadata.providers.push('nominatim_error');
      }
    }
    
    // Use fallback addresses if we still don't have enough
    if (rawSuggestions.length < 2) {
      console.log(`[${requestId}] Using fallback addresses for query: "${normalizedQuery}"`);
      const fallbackSuggestions = getFallbackOhioAddresses(normalizedQuery);
      
      if (fallbackSuggestions.length > 0) {
        const uniqueFallbacks = fallbackSuggestions.filter(fallback => {
          return !rawSuggestions.some(existing => 
            existing.address.toLowerCase() === fallback.address.toLowerCase() &&
            existing.city.toLowerCase() === fallback.city.toLowerCase()
          );
        });
        
        rawSuggestions = [...rawSuggestions, ...uniqueFallbacks].slice(0, resultLimit);
        metadata.providers.push('fallback');
      }
    }
    
    // If we still have no results, provide defaults
    if (rawSuggestions.length === 0) {
      rawSuggestions = [
        { address: "123 Main St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "default", confidence: "low" },
        { address: "456 High St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "default", confidence: "low" },
        { address: "789 Broad St", city: "Columbus", state: "OH", zipcode: "43215", verified: false, source: "default", confidence: "low" }
      ];
      metadata.providers.push('default');
    }
    
    // Format the response with clean address options
    const formattedAddresses = rawSuggestions.map((addr, index) => ({
      id: `addr_${index + 1}`,
      fullAddress: `${addr.address}, ${addr.city}, ${addr.state} ${addr.zipcode}`,
      address: addr.address,
      city: addr.city,
      state: addr.state,
      zipcode: addr.zipcode,
      verified: addr.verified || false,
      confidence: addr.confidence,
      source: addr.source,
      metadata: addr.metadata || {}
    }));
    
    // Create user-friendly options list
    const addressOptions = formattedAddresses.map(addr => ({
      value: addr.fullAddress,
      label: addr.fullAddress,
      verified: addr.verified,
      confidence: addr.confidence,
      id: addr.id
    }));
    
    metadata.count = formattedAddresses.length;
    metadata.source = metadata.providers[0] || 'unknown';
    
    const responseData = {
      addresses: formattedAddresses,
      options: addressOptions
    };
    
    // Cache the results
    cache.set(cacheKey, responseData);
    
    res.json({
      success: true,
      addresses: formattedAddresses,
      options: addressOptions,
      metadata
    });
    
  } catch (error) {
    console.error(`[${requestId}] Unexpected error:`, error);
    
    const emergencyAddresses = [
      {
        id: 'addr_emergency',
        fullAddress: '123 Main St, Columbus, OH 43215',
        address: '123 Main St',
        city: 'Columbus',
        state: 'OH',
        zipcode: '43215',
        verified: false,
        confidence: 'low',
        source: 'emergency',
        metadata: {}
      }
    ];
    
    const emergencyOptions = [
      {
        value: '123 Main St, Columbus, OH 43215',
        label: '123 Main St, Columbus, OH 43215',
        verified: false,
        confidence: 'low',
        id: 'addr_emergency'
      }
    ];
    
    res.json({
      success: true,
      addresses: emergencyAddresses,
      options: emergencyOptions,
      metadata: {
        query: req.query.query || '',
        count: 1,
        requestId,
        source: 'emergency',
        providers: ['emergency'],
        error: 'fallback_due_to_error'
      }
    });
  }
});

// New endpoint to get a formatted list of address options for dropdowns/selects
app.get('/api/address-options', async (req, res) => {
  try {
    const { query, limit = 8 } = req.query;
    
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter required',
        message: 'Please provide a query with at least 2 characters'
      });
    }
    
    // Call our main suggestions endpoint
    const suggestionResponse = await new Promise((resolve, reject) => {
      const req = { query: { query, limit } };
      const res = {
        json: (data) => resolve(data),
        status: (code) => ({ json: (data) => reject({ status: code, ...data }) })
      };
      
      // This would normally be an internal call, but for simplicity we'll make it work
      app._router.handle(req, res, () => {});
    });
    
    if (!suggestionResponse.success) {
      return res.status(400).json(suggestionResponse);
    }
    
    // Return just the clean options array
    res.json({
      success: true,
      options: suggestionResponse.options || [],
      count: suggestionResponse.options?.length || 0,
      query: query.trim()
    });
    
  } catch (error) {
    console.error('Address options error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch address options',
      options: []
    });
  }
});

app.get('/api/docs', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '2.1.0',
    documentation: {
      endpoints: {
        'GET /api/ohio-address-suggestions': {
          description: 'Search for Ohio address suggestions with detailed data',
          parameters: {
            query: 'string (required, min 2 chars)',
            limit: 'number (optional, 1-15, default 5)',
            format: 'string (optional, "standard" or "detailed")'
          },
          example: '/api/ohio-address-suggestions?query=123%20Main&limit=8',
          response: {
            addresses: 'Array of detailed address objects',
            options: 'Array of formatted options for dropdowns'
          }
        },
        'GET /api/address-options': {
          description: 'Get clean address options for form dropdowns/selects',
          parameters: {
            query: 'string (required, min 2 chars)',
            limit: 'number (optional, 1-15, default 8)'
          },
          example: '/api/address-options?query=123%20Main&limit=8',
          response: {
            options: 'Array of {value, label, verified, confidence, id}'
          }
        },
        'GET /api/test-smartystreets': {
          description: 'Test SmartyStreets API connection',
          parameters: {
            address: 'string (optional, default "1 Rosedale")',
            city: 'string (optional, default "Baltimore")',
            state: 'string (optional, default "MD")'
          },
          example: '/api/test-smartystreets?address=123%20Main&city=Columbus&state=OH'
        },
        'GET /api/test-fallback': 'Test fallback addresses',
        'GET /api/health': 'Health check with system stats',
        'GET /api/ping': 'Simple ping endpoint'
      },
      smartystreets: {
        configured: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
        required_env_vars: ['SMARTYSTREETS_AUTH_ID', 'SMARTYSTREETS_AUTH_TOKEN']
      },
      response_formats: {
        addresses: {
          id: 'Unique identifier for the address',
          fullAddress: 'Complete formatted address string',
          address: 'Street address',
          city: 'City name',
          state: 'State abbreviation',
          zipcode: 'ZIP code',
          verified: 'Boolean - if address is verified by SmartyStreets',
          confidence: 'high/medium/low/fallback',
          source: 'smartystreets/nominatim/fallback/default',
          metadata: 'Additional data about the address'
        },
        options: {
          value: 'Full address string for form submission',
          label: 'Display text for dropdown',
          verified: 'Boolean - if verified',
          confidence: 'Confidence level',
          id: 'Reference ID'
        }
      }
    }
  });
});

app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '2.1.0',
    status: 'operational',
    environment: process.env.NODE_ENV || 'development',
    docs: '/api/docs',
    smartystreets_configured: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN)
  });
});

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

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    availableEndpoints: [
      '/', 
      '/api/health', 
      '/api/ping', 
      '/api/ohio-address-suggestions', 
      '/api/address-options',
      '/api/test-smartystreets', 
      '/api/test-fallback', 
      '/api/docs'
    ]
  });
});

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
SmartyStreets: ${!!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) ? '✅ Configured' : '❌ Not Configured'}
Ready!
  `);
  
  // Validate SmartyStreets on startup
  if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
    validateSmartyStreetsConfig();
  }
  
  if (!isProduction) {
    setupKeepAlive();
  }
});

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
