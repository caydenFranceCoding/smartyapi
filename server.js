const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cluster = require('cluster');
const os = require('os');
require('dotenv').config();

if (cluster.isMaster && process.env.NODE_ENV === 'production') {
  const numWorkers = Math.min(os.cpus().length, 4);
  
  console.log(`Master process starting ${numWorkers} workers...`);
  
  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
  
  return;
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: [
    'https://app.hubspot.com', 
    'https://*.hubspot.com',
    'https://23263666.hubspotpreview-na1.com',
    'https://wattkarma.com',
    'https://localhost:3000'
  ],
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '1mb' }));

const axiosInstance = axios.create({
  timeout: 5000,
  maxRedirects: 3,
  httpAgent: new (require('http').Agent)({ 
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
    freeSocketTimeout: 30000
  }),
  httpsAgent: new (require('https').Agent)({ 
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
    freeSocketTimeout: 30000
  })
});

class FastCache {
  constructor(maxSize = 2000, ttl = 30 * 60 * 1000) {
    this.cache = new Map();
    this.accessTimes = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() - item.timestamp > this.ttl) {
      this.cache.delete(key);
      this.accessTimes.delete(key);
      return null;
    }
    
    this.accessTimes.set(key, Date.now());
    return item.data;
  }

  set(key, data) {
    if (this.cache.size >= this.maxSize) {
      this._evictOldest();
    }
    
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
    this.accessTimes.set(key, Date.now());
  }

  _evictOldest() {
    let oldestKey = null;
    let oldestTime = Date.now();
    
    for (const [key, time] of this.accessTimes) {
      if (time < oldestTime) {
        oldestTime = time;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.accessTimes.delete(oldestKey);
    }
  }

  clear() {
    const size = this.cache.size;
    this.cache.clear();
    this.accessTimes.clear();
    return size;
  }

  get size() {
    return this.cache.size;
  }
}

const cache = new FastCache(2000, 30 * 60 * 1000);

const rateLimitWindows = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS = 150;

function fastRateLimit(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  if (!rateLimitWindows.has(clientIP)) {
    rateLimitWindows.set(clientIP, [now]);
    return next();
  }

  const requests = rateLimitWindows.get(clientIP);
  
  const validRequests = requests.filter(time => time > windowStart);
  
  if (validRequests.length >= MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: Math.ceil((requests[0] + RATE_LIMIT_WINDOW - now) / 1000),
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }

  validRequests.push(now);
  rateLimitWindows.set(clientIP, validRequests);
  next();
}

app.use('/api/', fastRateLimit);

app.post('/api/batch-ohio-addresses', async (req, res) => {
  try {
    const { queries, limit = 5 } = req.body;
    
    if (!Array.isArray(queries) || queries.length === 0 || queries.length > 10) {
      return res.status(400).json({
        error: 'Invalid queries',
        message: 'Provide 1-10 address queries in an array',
        code: 'INVALID_BATCH_REQUEST'
      });
    }

    const results = await Promise.allSettled(
      queries.map(query => processOhioAddress(query, limit))
    );

    const responses = results.map((result, index) => ({
      query: queries[index],
      success: result.status === 'fulfilled',
      data: result.status === 'fulfilled' ? result.value : null,
      error: result.status === 'rejected' ? result.reason.message : null
    }));

    res.json({
      success: true,
      results: responses,
      processed: queries.length
    });

  } catch (error) {
    console.error('Batch processing error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Batch processing failed',
      code: 'BATCH_ERROR'
    });
  }
});

async function processOhioAddress(query, limit = 5) {
  if (!query || typeof query !== 'string' || query.trim().length < 3) {
    throw new Error('Query must be at least 3 characters');
  }

  const normalizedQuery = query.trim();
  const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
  const cacheKey = `ohio:${normalizedQuery.toLowerCase()}:${resultLimit}`;

  const cached = cache.get(cacheKey);
  if (cached) {
    return {
      suggestions: cached,
      metadata: { source: 'cache', cached: true, count: cached.length }
    };
  }

  console.log(`Processing address query: "${normalizedQuery}"`);

  if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
    try {
      console.log('Trying SmartyStreets...');
      const smartyResponse = await axiosInstance.get('https://us-street.api.smartystreets.com/street-address', {
        params: {
          'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
          'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
          street: normalizedQuery,
          state: 'OH',
          candidates: resultLimit,
          match: 'enhanced'
        },
        timeout: 4000
      });

      console.log(`SmartyStreets raw response:`, JSON.stringify(smartyResponse.data, null, 2));

      if (smartyResponse.data.length > 0) {
        const suggestions = smartyResponse.data
          .filter(addr => addr.components?.state_abbreviation === 'OH')
          .map(addr => {
            console.log('Processing SmartyStreets address:', JSON.stringify(addr, null, 2));
            const formatted = formatSmartyStreetsAddress(addr);
            console.log('Formatted result:', JSON.stringify(formatted, null, 2));
            return formatted;
          })
          .filter(Boolean) // Remove null results
          .slice(0, resultLimit);

        console.log('Final SmartyStreets suggestions:', JSON.stringify(suggestions, null, 2));

        if (suggestions.length > 0) {
          cache.set(cacheKey, suggestions);
          return {
            suggestions,
            metadata: {
              source: 'smartystreets',
              provider: 'SmartyStreets',
              count: suggestions.length,
              verified: true,
              cached: false
            }
          };
        } else {
          console.log('No valid SmartyStreets results after formatting, trying Nominatim...');
        }
      }
    } catch (error) {
      console.error('SmartyStreets error:', error.message);
      console.log('Falling back to Nominatim...');
    }
  }

  console.log('Using Nominatim fallback...');
  const nominatimPromises = [
    axiosInstance.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: `${normalizedQuery}, Ohio, USA`,
        format: 'json',
        addressdetails: 1,
        limit: resultLimit,
        countrycodes: 'us'
      },
      headers: { 'User-Agent': 'OhioEnergyAPI/1.0' },
      timeout: 6000
    })
  ];

  if (normalizedQuery.length > 10) {
    nominatimPromises.push(
      axiosInstance.get('https://nominatim.openstreetmap.org/search', {
        params: {
          street: normalizedQuery,
          state: 'Ohio',
          country: 'USA',
          format: 'json',
          addressdetails: 1,
          limit: Math.ceil(resultLimit / 2)
        },
        headers: { 'User-Agent': 'OhioEnergyAPI/1.0' },
        timeout: 6000
      })
    );
  }

  const responses = await Promise.allSettled(nominatimPromises);
  const allResults = responses
    .filter(r => r.status === 'fulfilled')
    .flatMap(r => {
      console.log('Nominatim raw response:', JSON.stringify(r.value.data, null, 2));
      return r.value.data;
    })
    .filter(addr => addr.address?.state?.toLowerCase().includes('ohio'))
    .map(addr => {
      console.log('Processing Nominatim address:', JSON.stringify(addr, null, 2));
      return formatNominatimAddress(addr);
    });

  const uniqueResults = allResults.filter((addr, index, arr) => 
    arr.findIndex(a => a.formatted === addr.formatted) === index
  ).slice(0, resultLimit);

  console.log('Final processed results:', JSON.stringify(uniqueResults, null, 2));

  cache.set(cacheKey, uniqueResults);

  return {
    suggestions: uniqueResults,
    metadata: {
      source: 'nominatim',
      provider: 'OpenStreetMap',
      count: uniqueResults.length,
      verified: false,
      cached: false
    }
  };
}

app.get('/api/ohio-address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5 } = req.query;
    const result = await processOhioAddress(query, limit);
    
    res.json({
      success: true,
      ...result
    });

  } catch (error) {
    if (error.message.includes('Query must be')) {
      return res.status(400).json({
        error: 'Invalid query parameter',
        message: error.message,
        code: 'INVALID_QUERY'
      });
    }

    console.error('Address suggestion error:', error.message);
    
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({
        success: false,
        error: 'Request timeout',
        message: 'Search took too long. Try being more specific.',
        code: 'TIMEOUT_ERROR'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

const COMMON_OHIO_CITIES = [
  'Columbus', 'Cleveland', 'Cincinnati', 'Toledo', 'Akron', 'Dayton'
];

async function preWarmCache() {
  console.log('Pre-warming cache with common Ohio cities...');
  
  const warmupPromises = COMMON_OHIO_CITIES.map(city => 
    processOhioAddress(city, 3).catch(err => 
      console.log(`Failed to warm cache for ${city}:`, err.message)
    )
  );
  
  await Promise.allSettled(warmupPromises);
  console.log('Cache pre-warming completed');
}

function formatSmartyStreetsAddress(addressData) {
  console.log('Raw SmartyStreets address data:', JSON.stringify(addressData, null, 2));
  
  const components = addressData.components || {};
  const metadata = addressData.metadata || {};
  
  // SmartyStreets might return data in different fields, let's try multiple approaches
  const street = addressData.delivery_line_1 || 
                 addressData.primary_number + ' ' + addressData.street_name || 
                 components.primary_number + ' ' + components.street_name || 
                 '';
  
  const city = components.city_name || 
               addressData.city_name || 
               components.default_city_name || 
               '';
  
  const state = components.state_abbreviation || 
                addressData.state_abbreviation || 
                'OH';
  
  const zipcode = components.zipcode || 
                  addressData.zipcode || 
                  components.plus4_code ? components.zipcode + '-' + components.plus4_code : components.zipcode ||
                  '';
  
  console.log('Extracted components:', { street, city, state, zipcode });
  
  // If we still don't have basic info, this might be an invalid response
  if (!street && !city && !zipcode) {
    console.log('Warning: No address components found in SmartyStreets response');
    return null; // Return null so this address gets filtered out
  }
  
  const cityStateZip = [city, state, zipcode].filter(Boolean).join(', ');
  const formatted = [street, cityStateZip].filter(Boolean).join(', ');
  
  return {
    formatted: formatted || `${city}, ${state} ${zipcode}`.trim(),
    street: street,
    city: city,
    state: state,
    zipcode: zipcode,
    postalCode: zipcode,
    country: 'US',
    latitude: parseFloat(metadata.latitude) || null,
    longitude: parseFloat(metadata.longitude) || null,
    county: metadata.county_name || '',
    verified: addressData.analysis?.dpv_match_y === 'Y',
    precision: 'USPS_VALIDATED',
    source: 'smartystreets'
  };
}

function formatNominatimAddress(addressData) {
  const address = addressData.address || {};
  
  const street = [
    address.house_number || '',
    address.road || ''
  ].filter(Boolean).join(' ').trim();
  
  const city = address.city || address.town || address.village || address.municipality || '';
  const state = address.state || 'OH';
  const zipcode = address.postcode || '';
  
  return {
    formatted: addressData.display_name || '',
    street: street,
    city: city,
    state: state,
    zipcode: zipcode,
    postalCode: zipcode,
    country: address.country || 'US',
    latitude: parseFloat(addressData.lat) || null,
    longitude: parseFloat(addressData.lon) || null,
    county: address.county || '',
    verified: false,
    precision: 'APPROXIMATE',
    source: 'nominatim'
  };
}

app.get('/api/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();

  res.json({
    success: true,
    status: 'operational',
    service: 'Ohio Address API',
    version: '1.0.1',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    worker: cluster.worker ? cluster.worker.id : 'master',
    uptime: {
      seconds: Math.floor(uptime),
      formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
    },
    cache: {
      size: cache.size,
      maxSize: cache.maxSize,
      hitRate: cache.hitRate || 0
    },
    memory: {
      used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
    },
    performance: {
      clustering: cluster.worker ? 'enabled' : 'disabled',
      connectionPooling: 'enabled',
      caching: 'enhanced'
    }
  });
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  cache.clear();
  process.exit(0);
});

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Worker ${cluster.worker?.id || 'single'} listening on port ${PORT}`);
  
  if (process.env.NODE_ENV === 'production') {
    setTimeout(preWarmCache, 5000);
  }
});
