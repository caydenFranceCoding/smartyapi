const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced logging middleware
const logRequest = (req, res, next) => {
  const start = Date.now();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - Request started`);
  
  // Log request details for debugging
  if (req.query && Object.keys(req.query).length > 0) {
    console.log('Query params:', req.query);
  }
  
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
    originalSend.call(this, data);
  };

  next();
};

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://localhost:3000',
      'http://localhost:3000'
    ];
    
    // Check for exact matches
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // Check for HubSpot domains (both regular and preview)
    if (origin.match(/^https:\/\/.*\.hubspot\.com$/) || 
        origin.match(/^https:\/\/.*\.hubspotpreview-na1\.com$/)) {
      return callback(null, true);
    }
    
    // For development, be more lenient
    if (process.env.NODE_ENV !== 'production') {
      console.log('Allowing origin for development:', origin);
      return callback(null, true);
    }
    
    // Reject other origins
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced rate limiting
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100;

function advancedRateLimit(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
  const now = Date.now();

  if (!requestCounts.has(clientIP)) {
    requestCounts.set(clientIP, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return next();
  }

  const clientData = requestCounts.get(clientIP);

  if (now > clientData.resetTime) {
    clientData.count = 1;
    clientData.resetTime = now + RATE_LIMIT_WINDOW;
    return next();
  }

  if (clientData.count >= MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP address',
      retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }

  clientData.count++;
  next();
}

app.use('/api/', advancedRateLimit);
app.use('/api/', logRequest);

// Enhanced caching system
const cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = 1000;

function getCachedResult(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    console.log(`Cache hit for key: ${key}`);
    return cached.data;
  }
  if (cached) {
    cache.delete(key);
    console.log(`Cache expired for key: ${key}`);
  }
  return null;
}

function setCachedResult(key, data) {
  // Implement cache size limit
  if (cache.size >= MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }

  cache.set(key, {
    data,
    timestamp: Date.now()
  });
  console.log(`Cached result for key: ${key}`);
}

// Enhanced address formatting
function formatSmartyStreetsAddress(addressData) {
  try {
    return {
      address: addressData.delivery_line_1 + (addressData.delivery_line_2 ? ' ' + addressData.delivery_line_2 : ''),
      city: addressData.components.city_name,
      state: addressData.components.state_abbreviation,
      zipcode: addressData.components.zipcode,
      verified: true
    };
  } catch (error) {
    console.error('Error formatting SmartyStreets address:', error);
    return null;
  }
}

function formatNominatimAddress(addressData) {
  try {
    return {
      address: addressData.address?.road || addressData.address?.house_number + ' ' + addressData.address?.road || '',
      city: addressData.address?.city || addressData.address?.town || addressData.address?.village || '',
      state: addressData.address?.state || '',
      zipcode: addressData.address?.postcode || '',
      verified: false
    };
  } catch (error) {
    console.error('Error formatting Nominatim address:', error);
    return null;
  }
}

// Environment variable validation
function validateEnvironment() {
  const smartyConfigured = process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN;
  console.log('Environment check:');
  console.log('- SmartyStreets configured:', smartyConfigured);
  console.log('- Node environment:', process.env.NODE_ENV || 'development');
  return { smartyConfigured };
}

// Primary Ohio address suggestions endpoint
app.get('/api/ohio-address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5 } = req.query;

    console.log(`Address search request: query="${query}", limit=${limit}`);

    // Input validation
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      console.log('Invalid query parameter');
      return res.status(400).json({
        error: 'Invalid query parameter',
        message: 'Query parameter is required and must be at least 2 characters long',
        code: 'INVALID_QUERY'
      });
    }

    const normalizedQuery = query.trim();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `ohio:${normalizedQuery.toLowerCase()}:${resultLimit}`;

    // Check cache first
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        suggestions: cached,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          count: cached.length,
          cached: true
        }
      });
    }

    console.log(`Searching for addresses: "${normalizedQuery}"`);

    let suggestions = [];
    let metadata = {
      query: normalizedQuery,
      count: 0,
      cached: false,
      attempts: []
    };

    // Try SmartyStreets first for maximum accuracy
    if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
      try {
        console.log('Attempting SmartyStreets lookup...');
        metadata.attempts.push('smartystreets');

        const smartyResponse = await axios.get('https://us-street.api.smartystreets.com/street-address', {
          params: {
            'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
            'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
            street: normalizedQuery,
            state: 'OH',
            candidates: resultLimit
          },
          timeout: 8000,
          headers: {
            'User-Agent': 'OhioEnergyAPI/1.0'
          }
        });

        console.log(`SmartyStreets response: ${smartyResponse.status}, ${smartyResponse.data.length} results`);

        if (smartyResponse.data && smartyResponse.data.length > 0) {
          suggestions = smartyResponse.data
            .filter(addr => addr.components?.state_abbreviation === 'OH')
            .map(formatSmartyStreetsAddress)
            .filter(addr => addr !== null)
            .slice(0, resultLimit);

          if (suggestions.length > 0) {
            metadata.source = 'smartystreets';
            metadata.provider = 'SmartyStreets';
            metadata.count = suggestions.length;
            metadata.verified = true;

            setCachedResult(cacheKey, suggestions);

            return res.json({
              success: true,
              suggestions,
              metadata
            });
          }
        }

      } catch (smartyError) {
        console.error('SmartyStreets error:', {
          status: smartyError.response?.status,
          statusText: smartyError.response?.statusText,
          message: smartyError.message,
          code: smartyError.code,
          url: smartyError.config?.url
        });

        // Log the full error for debugging
        if (smartyError.response?.data) {
          console.error('SmartyStreets error response:', smartyError.response.data);
        }

        metadata.smartystreetsError = smartyError.message;
        // Continue to fallback rather than failing completely
      }
    } else {
      console.log('SmartyStreets not configured, skipping...');
      metadata.attempts.push('smartystreets-not-configured');
    }

    // Fallback to Nominatim for broader coverage
    try {
      console.log('Using Nominatim fallback service...');
      metadata.attempts.push('nominatim');

      const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
        params: {
          q: `${normalizedQuery}, Ohio, USA`,
          format: 'json',
          addressdetails: 1,
          limit: resultLimit,
          countrycodes: 'us',
          'accept-language': 'en'
        },
        headers: {
          'User-Agent': 'OhioEnergyAPI/1.0 (Contact: admin@example.com)'
        },
        timeout: 10000
      });

      console.log(`Nominatim response: ${nominatimResponse.status}, ${nominatimResponse.data.length} results`);

      if (nominatimResponse.data && nominatimResponse.data.length > 0) {
        // Filter and format Ohio addresses
        suggestions = nominatimResponse.data
          .filter(addr => {
            const state = addr.address?.state?.toLowerCase();
            return state && state.includes('ohio');
          })
          .map(formatNominatimAddress)
          .filter(addr => addr !== null && addr.address)
          .slice(0, resultLimit);

        metadata.source = 'nominatim';
        metadata.provider = 'OpenStreetMap Nominatim';
        metadata.count = suggestions.length;
        metadata.verified = false;

        setCachedResult(cacheKey, suggestions);

        console.log(`Successfully processed ${suggestions.length} Ohio addresses from Nominatim`);
      }

    } catch (nominatimError) {
      console.error('Nominatim error:', {
        status: nominatimError.response?.status,
        statusText: nominatimError.response?.statusText,
        message: nominatimError.message,
        code: nominatimError.code
      });

      metadata.nominatimError = nominatimError.message;
    }

    // Return results (even if empty)
    res.json({
      success: true,
      suggestions,
      metadata
    });

  } catch (error) {
    console.error('Address suggestion error:', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      stack: error.stack
    });

    // Enhanced error handling
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return res.status(504).json({
        success: false,
        error: 'Request timeout',
        message: 'The address search took too long. Please try with more specific details.',
        code: 'TIMEOUT_ERROR'
      });
    }

    if (error.response?.status === 429) {
      return res.status(429).json({
        success: false,
        error: 'Service rate limit exceeded',
        message: 'The geocoding service is temporarily unavailable. Please try again shortly.',
        code: 'SERVICE_RATE_LIMIT'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Unable to process address search request',
      code: 'INTERNAL_ERROR',
      debug: process.env.NODE_ENV !== 'production' ? {
        message: error.message,
        code: error.code
      } : undefined
    });
  }
});

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
  const env = validateEnvironment();
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: env,
    endpoints: [
      '/api/health',
      '/api/ohio-address-suggestions',
      '/api/test'
    ]
  });
});

// System health and status endpoint
app.get('/api/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  const env = validateEnvironment();

  res.json({
    success: true,
    status: 'operational',
    service: 'Ohio Address API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    uptime: {
      seconds: Math.floor(uptime),
      formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
    },
    cache: {
      size: cache.size,
      maxSize: MAX_CACHE_SIZE,
      ttl: CACHE_TTL / 1000 + 's'
    },
    memory: {
      used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
    },
    providers: {
      smartystreets: env.smartyConfigured,
      nominatim: true
    },
    rateLimit: {
      window: RATE_LIMIT_WINDOW / 1000 + 's',
      maxRequests: MAX_REQUESTS
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '1.0.0',
    status: 'operational',
    endpoints: {
      health: '/api/health',
      test: '/api/test',
      search: '/api/ohio-address-suggestions?query=123+main+st&limit=5'
    }
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled application error:', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: 'An unexpected error occurred',
    code: 'INTERNAL_ERROR'
  });
});

// 404 handler
app.use('*', (req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    code: 'NOT_FOUND',
    availableEndpoints: [
      '/api/health',
      '/api/test',
      '/api/ohio-address-suggestions'
    ]
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  const env = validateEnvironment();
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    Ohio Address API Server                  ║
║                        Version 1.0.0                       ║
╠══════════════════════════════════════════════════════════════╣
║  Status: Running on port ${PORT}                                   ║
║  Environment: ${process.env.NODE_ENV || 'development'}                              ║
║  SmartyStreets: ${env.smartyConfigured ? 'Configured' : 'Not configured'}                           ║
║  Nominatim: Available                                        ║
║                                                              ║
║  Test your server:                                           ║
║  ${process.env.NODE_ENV === 'production' ? 'https://smartyapi.onrender.com' : `http://localhost:${PORT}`}/api/test                                    ║
║                                                              ║
║  Ready to serve Ohio address suggestions                     ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
