const express = require('express');
const cors = require('cors');
const axios = require('axios');

// Create Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: function(origin, callback) {
    if(!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://app.hubspot.com',
      'https://23263666.hubspotpreview-na1.com',
      'https://localhost:3000',
      'https://wattkarma.com',         
      'https://wattkarma.com/ohioinfo'   
    ];
    
    if(allowedOrigins.indexOf(origin) !== -1 || origin.match(/^https:\/\/[a-zA-Z0-9-]+\.hubspot\.com$/)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Simple in-memory cache for serverless
const cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

function getCachedResult(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  cache.delete(key);
  return null;
}

function setCachedResult(key, data) {
  // Limit cache size in serverless environment
  if (cache.size >= 100) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
  cache.set(key, { data, timestamp: Date.now() });
}

// Address formatting functions
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
    verified: true,
    source: 'smartystreets'
  };
}

function formatNominatimAddress(addressData) {
  return {
    formatted: addressData.display_name || '',
    street: addressData.address?.road || '',
    city: addressData.address?.city || addressData.address?.town || '',
    state: addressData.address?.state || '',
    country: addressData.address?.country || 'US',
    postalCode: addressData.address?.postcode || '',
    latitude: parseFloat(addressData.lat) || null,
    longitude: parseFloat(addressData.lon) || null,
    verified: false,
    source: 'nominatim'
  };
}

// Routes
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'operational',
    service: 'Ohio Address API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: 'production',
    providers: {
      smartystreets: !!process.env.SMARTYSTREETS_AUTH_ID,
      nominatim: true
    }
  });
});

app.get('/api/ohio-address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5 } = req.query;

    if (!query || typeof query !== 'string' || query.trim().length < 4) {
      return res.status(400).json({
        error: 'Invalid query parameter',
        message: 'Query parameter is required and must be at least 4 characters long'
      });
    }

    const normalizedQuery = query.trim();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `ohio:${normalizedQuery.toLowerCase()}:${resultLimit}`;

    // Check cache
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        suggestions: cached,
        metadata: { source: 'cache', cached: true }
      });
    }

    //  SmartyStreets first
    if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
      try {
        const smartyResponse = await axios.get('https://us-street.api.smartystreets.com/street-address', {
          params: {
            'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
            'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
            street: normalizedQuery,
            state: 'OH',
            candidates: resultLimit
          },
          timeout: 5000
        });

        if (smartyResponse.data.length > 0) {
          const suggestions = smartyResponse.data
            .filter(addr => addr.components?.state_abbreviation === 'OH')
            .map(formatSmartyStreetsAddress)
            .slice(0, resultLimit);

          setCachedResult(cacheKey, suggestions);
          return res.json({
            success: true,
            suggestions,
            metadata: { source: 'smartystreets', verified: true }
          });
        }
      } catch (smartyError) {
        console.error('SmartyStreets error:', smartyError.message);
      }
    }

    // Fallback to Nominatim
    const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: `${normalizedQuery}, OH`,
        format: 'json',
        addressdetails: 1,
        limit: resultLimit,
        countrycodes: 'us'
      },
      headers: { 'User-Agent': 'OhioEnergyAPI/1.0' },
      timeout: 8000
    });

    const suggestions = nominatimResponse.data
      .filter(addr => addr.address?.state?.toLowerCase().includes('ohio'))
      .map(formatNominatimAddress)
      .slice(0, resultLimit);

    setCachedResult(cacheKey, suggestions);
    res.json({
      success: true,
      suggestions,
      metadata: { source: 'nominatim', verified: false }
    });

  } catch (error) {
    console.error('Address suggestion error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Unable to process address search request'
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Ohio Address API',
    version: '1.0.0',
    status: 'operational',
    endpoints: ['/api/health', '/api/ohio-address-suggestions']
  });
});

// Catch all for API routes
app.get('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`
  });
});

module.exports = app;
