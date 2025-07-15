const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Enable trust proxy for proper IP detection
app.set('trust proxy', true);

// Enhanced CORS
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
    console.log('Allowing origin:', origin);
    return callback(null, true);
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
  try {
    const clientIP = req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
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
        success: false,
        error: 'Rate limit exceeded',
        message: 'Too many requests from this IP address',
        retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
        code: 'RATE_LIMIT_EXCEEDED'
      });
    }

    clientData.count++;
    next();
  } catch (error) {
    console.error('Rate limiting error:', error);
    next(); // Continue on rate limit error
  }
}

app.use('/api/', advancedRateLimit);

// Enhanced caching system
const cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = 1000;

function getCachedResult(key) {
  try {
    const cached = cache.get(key);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
    if (cached) {
      cache.delete(key);
    }
    return null;
  } catch (error) {
    console.error('Cache retrieval error:', error);
    return null;
  }
}

function setCachedResult(key, data) {
  try {
    // Implement cache size limit
    if (cache.size >= MAX_CACHE_SIZE) {
      const firstKey = cache.keys().next().value;
      cache.delete(firstKey);
    }

    cache.set(key, {
      data,
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Cache storage error:', error);
  }
}

// Safe address formatting functions
function formatSmartyStreetsAddress(addressData) {
  try {
    if (!addressData || !addressData.components) {
      console.warn('Invalid SmartyStreets address data:', addressData);
      return null;
    }

    return {
      address: (addressData.delivery_line_1 || '') + (addressData.delivery_line_2 ? ' ' + addressData.delivery_line_2 : ''),
      city: addressData.components.city_name || '',
      state: addressData.components.state_abbreviation || 'OH',
      zipcode: addressData.components.zipcode || '',
      verified: true
    };
  } catch (error) {
    console.error('Error formatting SmartyStreets address:', error);
    return null;
  }
}

function formatNominatimAddress(addressData) {
  try {
    if (!addressData) {
      console.warn('Invalid Nominatim address data:', addressData);
      return null;
    }

    const address = addressData.address || {};
    
    // Build street address
    let streetAddress = '';
    if (address.house_number && address.road) {
      streetAddress = `${address.house_number} ${address.road}`;
    } else if (address.road) {
      streetAddress = address.road;
    } else if (addressData.display_name) {
      // Fallback to first part of display name
      streetAddress = addressData.display_name.split(',')[0] || '';
    }

    return {
      address: streetAddress,
      city: address.city || address.town || address.village || '',
      state: address.state || 'OH',
      zipcode: address.postcode || '',
      verified: false
    };
  } catch (error) {
    console.error('Error formatting Nominatim address:', error);
    return null;
  }
}

// Request logging middleware
function logRequest(req, res, next) {
  const start = Date.now();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - Started`);
  
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
}

app.use('/api/', logRequest);

// Test endpoint
app.get('/api/test', (req, res) => {
  console.log('Test endpoint called');
  res.json({
    success: true,
    message: 'Server is working properly!',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    smartystreets: {
      configured: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
      authId: process.env.SMARTYSTREETS_AUTH_ID ? 'Set' : 'Not set',
      authToken: process.env.SMARTYSTREETS_AUTH_TOKEN ? 'Set' : 'Not set'
    }
  });
});

// BULLETPROOF ADDRESS SEARCH ENDPOINT
app.get('/api/ohio-address-suggestions', async (req, res) => {
  console.log('\n=== ADDRESS SEARCH REQUEST ===');
  
  try {
    const { query, limit = 5 } = req.query;
    console.log('Request params:', { query, limit });

    // Input validation with detailed logging
    if (!query) {
      console.log('Missing query parameter');
      return res.status(400).json({
        success: false,
        error: 'Missing query parameter',
        message: 'Query parameter is required',
        code: 'MISSING_QUERY'
      });
    }

    if (typeof query !== 'string') {
      console.log('Invalid query type:', typeof query);
      return res.status(400).json({
        success: false,
        error: 'Invalid query type',
        message: 'Query must be a string',
        code: 'INVALID_QUERY_TYPE'
      });
    }

    const normalizedQuery = query.trim();
    if (normalizedQuery.length < 2) {
      console.log('Query too short:', normalizedQuery.length);
      return res.status(400).json({
        success: false,
        error: 'Query too short',
        message: 'Query must be at least 2 characters long',
        code: 'QUERY_TOO_SHORT'
      });
    }

    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `ohio:${normalizedQuery.toLowerCase()}:${resultLimit}`;

    console.log(`Processing search for: "${normalizedQuery}" (limit: ${resultLimit})`);

    // Check cache first
    const cached = getCachedResult(cacheKey);
    if (cached) {
      console.log('Returning cached result');
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

    let suggestions = [];
    let metadata = {
      query: normalizedQuery,
      count: 0,
      cached: false,
      attempts: []
    };

    // Try SmartyStreets first
    const smartyConfigured = !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN);
    console.log('SmartyStreets configured:', smartyConfigured);

    if (smartyConfigured) {
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
          },
          validateStatus: function (status) {
            return status < 500; // Accept any status less than 500
          }
        });

        console.log(`SmartyStreets response: status=${smartyResponse.status}, data length=${smartyResponse.data?.length || 0}`);

        if (smartyResponse.status === 200 && smartyResponse.data && Array.isArray(smartyResponse.data) && smartyResponse.data.length > 0) {
          const smartySuggestions = smartyResponse.data
            .map(formatSmartyStreetsAddress)
            .filter(addr => addr !== null && addr.address && addr.state === 'OH')
            .slice(0, resultLimit);

          if (smartySuggestions.length > 0) {
            suggestions = smartySuggestions;
            metadata.source = 'smartystreets';
            metadata.provider = 'SmartyStreets';
            metadata.count = smartySuggestions.length;
            metadata.verified = true;

            setCachedResult(cacheKey, suggestions);

            console.log(`Successfully found ${suggestions.length} SmartyStreets results`);
            console.log('=== END REQUEST (SUCCESS) ===\n');

            return res.json({
              success: true,
              suggestions,
              metadata
            });
          }
        } else if (smartyResponse.status !== 200) {
          console.log(`SmartyStreets returned status ${smartyResponse.status}:`, smartyResponse.data);
        }

      } catch (smartyError) {
        console.error('SmartyStreets error:', {
          message: smartyError.message,
          status: smartyError.response?.status,
          statusText: smartyError.response?.statusText,
          code: smartyError.code
        });
        metadata.smartystreetsError = smartyError.message;
      }
    } else {
      console.log('SmartyStreets not configured, skipping...');
      metadata.attempts.push('smartystreets-not-configured');
    }

    // Fallback to Nominatim
    try {
      console.log('Attempting Nominatim lookup...');
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
          'User-Agent': 'OhioEnergyAPI/1.0 (contact@example.com)'
        },
        timeout: 10000,
        validateStatus: function (status) {
          return status < 500; // Accept any status less than 500
        }
      });

      console.log(`Nominatim response: status=${nominatimResponse.status}, data length=${nominatimResponse.data?.length || 0}`);

      if (nominatimResponse.status === 200 && nominatimResponse.data && Array.isArray(nominatimResponse.data) && nominatimResponse.data.length > 0) {
        // Filter and format Ohio addresses
        const nominatimSuggestions = nominatimResponse.data
          .filter(addr => {
            const state = addr.address?.state?.toLowerCase();
            return state && (state.includes('ohio') || state === 'oh');
          })
          .map(formatNominatimAddress)
          .filter(addr => addr !== null && addr.address)
          .slice(0, resultLimit);

        if (nominatimSuggestions.length > 0) {
          suggestions = nominatimSuggestions;
          metadata.source = 'nominatim';
          metadata.provider = 'OpenStreetMap Nominatim';
          metadata.count = nominatimSuggestions.length;
          metadata.verified = false;

          setCachedResult(cacheKey, suggestions);
          console.log(`Successfully found ${suggestions.length} Nominatim results`);
        }
      } else if (nominatimResponse.status !== 200) {
        console.log(`Nominatim returned status ${nominatimResponse.status}:`, nominatimResponse.data);
      }

    } catch (nominatimError) {
      console.error('Nominatim error:', {
        message: nominatimError.message,
        status: nominatimError.response?.status,
        statusText: nominatimError.response?.statusText,
        code: nominatimError.code
      });
      metadata.nominatimError = nominatimError.message;
    }

    // Return results (even if empty)
    console.log(`Final result: ${suggestions.length} suggestions from ${metadata.source || 'no source'}`);
    console.log('=== END REQUEST ===\n');

    res.json({
      success: true,
      suggestions,
      metadata
    });

  } catch (error) {
    console.error('Unexpected error in address search:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });

    console.log('=== END REQUEST (ERROR) ===\n');

    // Return a more specific error based on the type
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
        name: error.name
      } : undefined
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  try {
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();

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
        smartystreets: !!(process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN),
        nominatim: true
      },
      rateLimit: {
        window: RATE_LIMIT_WINDOW / 1000 + 's',
        maxRequests: MAX_REQUESTS
      }
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      success: false,
      error: 'Health check failed',
      message: error.message
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '1.0.0',
    status: 'operational',
    documentation: '/api/test',
    health: '/api/health',
    endpoints: [
      '/api/test',
      '/api/health',
      '/api/ohio-address-suggestions'
    ]
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler caught:', {
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
    code: 'GLOBAL_ERROR'
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
      '/api/test',
      '/api/health',
      '/api/ohio-address-suggestions'
    ]
  });
});

// Start server with error handling
const server = app.listen(PORT, '0.0.0.0', (error) => {
  if (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
  
  console.log(`
🚀 BULLETPROOF OHIO ADDRESS API SERVER
📍 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV || 'development'}
🔑 SmartyStreets: ${process.env.SMARTYSTREETS_AUTH_ID ? 'Configured ✅' : 'Not configured ❌'}
🗺️  Nominatim: Available ✅

📋 Test endpoints:
   GET / 
   GET /api/test
   GET /api/health
   GET /api/ohio-address-suggestions?query=main&limit=5

🔧 Server ready and bulletproof!
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = app;
