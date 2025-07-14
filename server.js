const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://localhost:3000'
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
    
    // Reject other origins
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// Enhanced rate limiting
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100;

function advancedRateLimit(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
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

// Enhanced caching system
const cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = 1000;

function getCachedResult(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  cache.delete(key);
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
}

// Enhanced address formatting
function formatSmartyStreetsAddress(addressData) {
  return {
    formatted: [
      addressData.delivery_line_1,
      addressData.delivery_line_2,
      `${addressData.components.city_name}, ${addressData.components.state_abbreviation} ${addressData.components.zipcode}`
    ].filter(Boolean).join(', '),
    street: addressData.delivery_line_1 + (addressData.delivery_line_2 ? ' ' + addressData.delivery_line_2 : ''),
    city: addressData.components.city_name,
    state: addressData.components.state_abbreviation,
    country: 'US',
    postalCode: addressData.components.zipcode,
    latitude: parseFloat(addressData.metadata?.latitude) || null,
    longitude: parseFloat(addressData.metadata?.longitude) || null,
    county: addressData.metadata?.county_name || '',
    verified: addressData.analysis?.dpv_match_y === 'Y',
    precision: 'USPS_VALIDATED',
    source: 'smartystreets'
  };
}

function formatNominatimAddress(addressData) {
  return {
    formatted: addressData.display_name || '',
    street: addressData.address?.road || '',
    city: addressData.address?.city || addressData.address?.town || addressData.address?.village || '',
    state: addressData.address?.state || '',
    country: addressData.address?.country || 'US',
    postalCode: addressData.address?.postcode || '',
    latitude: parseFloat(addressData.lat) || null,
    longitude: parseFloat(addressData.lon) || null,
    county: addressData.address?.county || '',
    verified: false,
    precision: 'APPROXIMATE',
    source: 'nominatim'
  };
}

// Request logging middleware
function logRequest(req, res, next) {
  const start = Date.now();
  const originalSend = res.send;

  res.send = function(data) {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
    originalSend.call(this, data);
  };

  next();
}

app.use('/api/', logRequest);

// Primary Ohio address suggestions endpoint
app.get('/api/ohio-address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5 } = req.query;

    // Input validation
    if (!query || typeof query !== 'string' || query.trim().length < 4) {
      return res.status(400).json({
        error: 'Invalid query parameter',
        message: 'Query parameter is required and must be at least 4 characters long',
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

    console.log(`Address search initiated: "${normalizedQuery}"`);

    // Try SmartyStreets first for maximum accuracy
    if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
      try {
        console.log('Attempting SmartyStreets lookup...');

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

        console.log(`SmartyStreets returned ${smartyResponse.data.length} results`);

        if (smartyResponse.data.length > 0) {
          const smartySuggestions = smartyResponse.data
            .filter(addr => addr.components?.state_abbreviation === 'OH')
            .map(formatSmartyStreetsAddress)
            .slice(0, resultLimit);

          setCachedResult(cacheKey, smartySuggestions);

          return res.json({
            success: true,
            suggestions: smartySuggestions,
            metadata: {
              source: 'smartystreets',
              provider: 'SmartyStreets',
              query: normalizedQuery,
              count: smartySuggestions.length,
              verified: true,
              cached: false
            }
          });
        }

      } catch (smartyError) {
        console.error('SmartyStreets error:', {
          status: smartyError.response?.status,
          message: smartyError.message,
          code: smartyError.code
        });

        // Continue to fallback rather than failing completely
        console.log('Falling back to Nominatim geocoding service...');
      }
    }

    // Fallback to Nominatim for broader coverage
    console.log('Using Nominatim fallback service...');

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
        'User-Agent': 'OhioEnergyAPI/1.0'
      },
      timeout: 10000
    });

    console.log(`Nominatim returned ${nominatimResponse.data.length} raw results`);

    // Filter and format Ohio addresses
    const ohioSuggestions = nominatimResponse.data
      .filter(addr => {
        const state = addr.address?.state?.toLowerCase();
        return state && state.includes('ohio');
      })
      .map(formatNominatimAddress)
      .slice(0, resultLimit);

    setCachedResult(cacheKey, ohioSuggestions);

    console.log(`Processed ${ohioSuggestions.length} Ohio addresses`);

    res.json({
      success: true,
      suggestions: ohioSuggestions,
      metadata: {
        source: 'nominatim',
        provider: 'OpenStreetMap',
        query: normalizedQuery,
        count: ohioSuggestions.length,
        verified: false,
        cached: false
      }
    });

  } catch (error) {
    console.error('Address suggestion error:', {
      message: error.message,
      code: error.code,
      status: error.response?.status
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
      code: 'INTERNAL_ERROR'
    });
  }
});

// General address suggestions endpoint
app.get('/api/address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5, country = 'us' } = req.query;

    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Invalid query parameter',
        message: 'Query parameter is required and must be at least 2 characters long',
        code: 'INVALID_QUERY'
      });
    }

    const normalizedQuery = query.trim();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `general:${normalizedQuery.toLowerCase()}:${resultLimit}:${country}`;

    const cached = getCachedResult(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        suggestions: cached,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          country: country,
          count: cached.length,
          cached: true
        }
      });
    }

    console.log(`General address search: "${normalizedQuery}" (${country})`);

    // Use Nominatim for international and general searches
    const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: normalizedQuery,
        format: 'json',
        addressdetails: 1,
        limit: resultLimit,
        countrycodes: country.toLowerCase(),
        'accept-language': 'en'
      },
      headers: {
        'User-Agent': 'AddressAPI/1.0'
      },
      timeout: 10000
    });

    const suggestions = nominatimResponse.data.map(formatNominatimAddress);
    setCachedResult(cacheKey, suggestions);

    res.json({
      success: true,
      suggestions,
      metadata: {
        source: 'nominatim',
        provider: 'OpenStreetMap',
        query: normalizedQuery,
        country: country,
        count: suggestions.length,
        cached: false
      }
    });

  } catch (error) {
    console.error('General address search error:', error.message);

    res.status(500).json({
      success: false,
      error: 'Address search failed',
      message: 'Unable to process address search request',
      code: 'SEARCH_ERROR'
    });
  }
});

// Address validation endpoint
app.post('/api/validate-address', async (req, res) => {
  try {
    const { address } = req.body;

    if (!address || typeof address !== 'string' || !address.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Invalid address',
        message: 'Address is required in request body',
        code: 'INVALID_ADDRESS'
      });
    }

    const normalizedAddress = address.trim();
    const cacheKey = `validate:${normalizedAddress.toLowerCase()}`;

    const cached = getCachedResult(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    console.log(`Address validation request: "${normalizedAddress}"`);

    // Try SmartyStreets for US addresses first
    if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
      try {
        const smartyResponse = await axios.get('https://us-street.api.smartystreets.com/street-address', {
          params: {
            'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
            'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
            street: normalizedAddress,
            candidates: 1
          },
          timeout: 8000
        });

        if (smartyResponse.data.length > 0) {
          const validatedAddress = formatSmartyStreetsAddress(smartyResponse.data[0]);
          const result = {
            success: true,
            valid: true,
            address: validatedAddress,
            confidence: 0.95,
            provider: 'SmartyStreets'
          };

          setCachedResult(cacheKey, result);
          return res.json(result);
        }
      } catch (smartyError) {
        console.log('SmartyStreets validation failed, trying Nominatim...');
      }
    }

    // Fallback to Nominatim
    const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: normalizedAddress,
        format: 'json',
        addressdetails: 1,
        limit: 1,
        countrycodes: 'us'
      },
      headers: {
        'User-Agent': 'AddressAPI/1.0'
      },
      timeout: 10000
    });

    if (nominatimResponse.data.length === 0) {
      const result = {
        success: true,
        valid: false,
        message: 'Address not found',
        provider: 'Nominatim'
      };
      setCachedResult(cacheKey, result);
      return res.json(result);
    }

    const validatedAddress = formatNominatimAddress(nominatimResponse.data[0]);
    const result = {
      success: true,
      valid: true,
      address: validatedAddress,
      confidence: 0.75,
      provider: 'Nominatim'
    };

    setCachedResult(cacheKey, result);
    res.json(result);

  } catch (error) {
    console.error('Address validation error:', error.message);

    res.status(500).json({
      success: false,
      error: 'Validation failed',
      message: 'Unable to validate address',
      code: 'VALIDATION_ERROR'
    });
  }
});

// Ohio ZIP code validation
app.get('/api/validate-ohio-zip', async (req, res) => {
  try {
    const { zip } = req.query;

    if (!zip || !/^\d{5}$/.test(zip)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid ZIP code',
        message: 'Valid 5-digit ZIP code is required',
        code: 'INVALID_ZIP'
      });
    }

    console.log(`ZIP code validation: ${zip}`);

    // Basic Ohio ZIP validation (starts with 4)
    const isOhioPattern = zip.startsWith('4');

    if (!isOhioPattern) {
      return res.json({
        success: true,
        valid: false,
        ohio: false,
        message: 'ZIP code pattern does not match Ohio'
      });
    }

    // Enhanced validation with geocoding
    try {
      const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
        params: {
          postalcode: zip,
          country: 'us',
          format: 'json',
          addressdetails: 1,
          limit: 1
        },
        headers: {
          'User-Agent': 'AddressAPI/1.0'
        },
        timeout: 5000
      });

      if (nominatimResponse.data.length > 0) {
        const zipData = nominatimResponse.data[0];
        const isOhio = zipData.address?.state?.toLowerCase().includes('ohio');

        return res.json({
          success: true,
          valid: true,
          ohio: isOhio,
          city: zipData.address?.city || zipData.address?.town || 'Unknown',
          state: zipData.address?.state || 'OH',
          county: zipData.address?.county || '',
          coordinates: {
            latitude: parseFloat(zipData.lat) || null,
            longitude: parseFloat(zipData.lon) || null
          }
        });
      }
    } catch (geoError) {
      // Fallback to basic validation
      console.log('Geocoding failed, using basic validation');
    }

    // Basic fallback response
    res.json({
      success: true,
      valid: true,
      ohio: true,
      city: 'Unknown',
      state: 'OH',
      message: 'Basic pattern validation - ZIP appears to be in Ohio'
    });

  } catch (error) {
    console.error('ZIP validation error:', error.message);

    res.status(500).json({
      success: false,
      error: 'ZIP validation failed',
      message: 'Unable to validate ZIP code',
      code: 'ZIP_VALIDATION_ERROR'
    });
  }
});

// Reverse geocoding endpoint
app.get('/api/reverse-geocode', async (req, res) => {
  try {
    const { lat, lng } = req.query;

    if (!lat || !lng) {
      return res.status(400).json({
        success: false,
        error: 'Missing coordinates',
        message: 'Both lat and lng parameters are required',
        code: 'INVALID_COORDINATES'
      });
    }

    const latitude = parseFloat(lat);
    const longitude = parseFloat(lng);

    if (isNaN(latitude) || isNaN(longitude)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid coordinates',
        message: 'Latitude and longitude must be valid numbers',
        code: 'INVALID_COORDINATE_FORMAT'
      });
    }

    const cacheKey = `reverse:${latitude.toFixed(6)}:${longitude.toFixed(6)}`;
    const cached = getCachedResult(cacheKey);

    if (cached) {
      return res.json(cached);
    }

    console.log(`Reverse geocoding: ${latitude}, ${longitude}`);

    const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/reverse', {
      params: {
        lat: latitude,
        lon: longitude,
        format: 'json',
        addressdetails: 1
      },
      headers: {
        'User-Agent': 'AddressAPI/1.0'
      },
      timeout: 8000
    });

    const address = formatNominatimAddress(nominatimResponse.data);
    const result = {
      success: true,
      address,
      coordinates: { latitude, longitude },
      provider: 'Nominatim'
    };

    setCachedResult(cacheKey, result);
    res.json(result);

  } catch (error) {
    console.error('Reverse geocoding error:', error.message);

    res.status(500).json({
      success: false,
      error: 'Reverse geocoding failed',
      message: 'Unable to convert coordinates to address',
      code: 'REVERSE_GEOCODING_ERROR'
    });
  }
});

// System health and status endpoint
app.get('/api/health', (req, res) => {
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
      smartystreets: !!process.env.SMARTYSTREETS_AUTH_ID,
      nominatim: true
    },
    rateLimit: {
      window: RATE_LIMIT_WINDOW / 1000 + 's',
      maxRequests: MAX_REQUESTS
    }
  });
});

// Cache management endpoint
app.post('/api/cache/clear', (req, res) => {
  const previousSize = cache.size;
  cache.clear();

  console.log(`Cache cleared: ${previousSize} entries removed`);

  res.json({
    success: true,
    message: 'Cache cleared successfully',
    entriesRemoved: previousSize,
    timestamp: new Date().toISOString()
  });
});

// API documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    service: 'Ohio Address Suggestions API',
    version: '1.0.0',
    description: 'Professional address validation and geocoding service for Ohio energy enrollment',
    baseUrl: req.protocol + '://' + req.get('host') + '/api',
    endpoints: {
      'GET /health': {
        description: 'Service health check and system information',
        parameters: {},
        response: 'System status and performance metrics'
      },
      'GET /ohio-address-suggestions': {
        description: 'Get Ohio-specific address suggestions with USPS validation',
        parameters: {
          query: 'Address search query (minimum 4 characters)',
          limit: 'Maximum results to return (1-10, default: 5)'
        },
        example: '/api/ohio-address-suggestions?query=1+Nationwide+Plaza&limit=5'
      },
      'GET /address-suggestions': {
        description: 'General address suggestions for any country',
        parameters: {
          query: 'Address search query (minimum 2 characters)',
          limit: 'Maximum results to return (1-10, default: 5)',
          country: 'ISO country code (default: us)'
        },
        example: '/api/address-suggestions?query=123+Main+Street&country=us'
      },
      'POST /validate-address': {
        description: 'Validate and standardize a complete address',
        body: { address: 'Complete address string' },
        response: 'Validation result with confidence score'
      },
      'GET /validate-ohio-zip': {
        description: 'Validate Ohio ZIP codes with location details',
        parameters: { zip: '5-digit ZIP code' },
        example: '/api/validate-ohio-zip?zip=43215'
      },
      'GET /reverse-geocode': {
        description: 'Convert coordinates to street address',
        parameters: {
          lat: 'Latitude (decimal degrees)',
          lng: 'Longitude (decimal degrees)'
        },
        example: '/api/reverse-geocode?lat=39.9612&lng=-82.9988'
      }
    },
    authentication: 'None required',
    rateLimit: `${MAX_REQUESTS} requests per ${RATE_LIMIT_WINDOW / 60000} minutes`,
    caching: `${CACHE_TTL / 60000} minute TTL`
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '1.0.0',
    status: 'operational',
    documentation: '/api/docs',
    health: '/api/health'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled application error:', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method
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
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    code: 'NOT_FOUND',
    availableEndpoints: [
      '/api/health',
      '/api/docs',
      '/api/ohio-address-suggestions',
      '/api/address-suggestions',
      '/api/validate-address',
      '/api/validate-ohio-zip',
      '/api/reverse-geocode'
    ]
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    Ohio Address API Server                  ║
║                        Version 1.0.0                       ║
╠══════════════════════════════════════════════════════════════╣
║  Status: Running on port ${PORT}                                   ║
║  Environment: ${process.env.NODE_ENV || 'development'}                              ║
║  Health: ${process.env.NODE_ENV === 'production' ? 'https://[your-app].onrender.com' : `http://localhost:${PORT}`}/api/health            ║
║  Docs:   ${process.env.NODE_ENV === 'production' ? 'https://[your-app].onrender.com' : `http://localhost:${PORT}`}/api/docs              ║
║                                                              ║
║  Providers:                                                  ║
║    • SmartyStreets: ${process.env.SMARTYSTREETS_AUTH_ID ? 'Enabled' : 'Disabled'}                             ║
║    • Nominatim:     Enabled                                  ║
║                                                              ║
║  Ready to serve Ohio address suggestions                     ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
